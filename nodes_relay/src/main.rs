use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, identify, noise, ping, relay, rendezvous,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::{error::Error, time::Duration};
mod manage_key;
mod metrics;
use manage_key::load_or_generate_keypair;

#[derive(NetworkBehaviour)]
struct RelayServerBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    // Point de rendezvous pour la découverte de pairs par namespace (les
    // nœuds `nux` s'y enregistrent/interrogent via `rendezvous::client`).
    // N'authentifie rien : seul le challenge-response `/nux/auth/1.0.0`
    // qui suit une découverte fait foi.
    rendezvous: rendezvous::server::Behaviour,
}

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "nux-relay",
    version,
    about = "Tunnels P2P chiffrés et authentifiés, sans VPN"
)]
struct Cli {
    #[arg(long = "port", default_value_t = 4001)]
    port: u16,

    #[arg(long = "key-path", default_value = "relay_identity.key")]
    key_path: PathBuf,

    /// Adresse publique de ce relay (répétable), ex.
    /// `/ip4/203.0.113.10/tcp/4001`. Sans elle, le relay ne peut confirmer
    /// aucune adresse externe : `identify` ne peut l'apprendre par
    /// observation que si un pair connecté le supporte lui-même, ce
    /// qu'aucun nœud `nux` (Client/Guard) ne fait. Sans adresse externe
    /// confirmée, toute réservation de circuit échoue
    /// (`NoAddressesInReservation`) — silencieusement, et de façon non
    /// déterministe selon les interfaces détectées localement.
    #[arg(long = "external-address")]
    external_address: Vec<Multiaddr>,
}

/// Écrit périodiquement l'instantané Prometheus dans le fichier lu par le
/// textfile collector de `node_exporter`. Écriture atomique (fichier
/// temporaire puis renommage) : un scrape concurrent ne lit jamais un
/// contenu tronqué. Un échec d'écriture (répertoire absent, permissions) est
/// silencieux et sans effet sur le service du relay — les métriques sont un
/// à-côté, jamais une condition de fonctionnement.
pub fn spawn_metrics_writer(metrics: Arc<metrics::Metrics>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let tmp = "/var/lib/node_exporter/textfile_collector/node_relay.prom.tmp";
            let dest = "/var/lib/node_exporter/textfile_collector/node_relay.prom";
            if tokio::fs::write(tmp, metrics.to_prometheus_text())
                .await
                .is_ok()
            {
                let _ = tokio::fs::rename(tmp, dest).await;
            }
        }
    });
}

/// Rafraîchit toutes les 5 s la date de modification de `path`, sur lequel
/// s'appuie le `HEALTHCHECK` du conteneur (`find <path> -mmin -1`) : tant que
/// la boucle d'événements tourne (ce heartbeat lui est concurrent, pas
/// séquentiel), le fichier reste « frais » et le conteneur est considéré sain.
pub fn spawn_readiness_heartbeat(path: &'static str) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let _ = tokio::fs::write(path, b"").await;
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    // 1. Parse les arguments CLI
    let cli = Cli::parse();

    // 2. Charge/génère l'identité (on emprunte le champ, pas besoin de destructurer)
    let keypair = load_or_generate_keypair(&cli.key_path)?;
    let local_peer_id = PeerId::from(keypair.public());
    println!("Relay PeerId: {local_peer_id}");

    // 3. Construction du swarm
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|kp| RelayServerBehaviour {
            relay: relay::Behaviour::new(
                kp.public().to_peer_id(),
                relay::Config {
                    max_reservations: 128,
                    max_reservations_per_peer: 4,
                    max_circuits: 16,
                    max_circuits_per_peer: 4,
                    max_circuit_duration: std::time::Duration::from_secs(2 * 60),
                    max_circuit_bytes: 1 << 20,
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/mon-proto/1.0.0".into(),
                kp.public(),
            )),
            ping: ping::Behaviour::default(),
            rendezvous: rendezvous::server::Behaviour::new(rendezvous::server::Config::default()),
        })?
        // Sans ceci, `idle_connection_timeout` vaut `Duration::ZERO` par
        // défaut : toute connexion sans substream actif à l'instant T est
        // fermée immédiatement, y compris juste après l'acceptation d'une
        // réservation — un client (Guard/nux) se reconnecte alors en
        // boucle pour la maintenir. 60 s laisse la réservation (et le futur
        // trafic relayé) respirer sans connexion active continue.
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(60))
        })
        .build();

    // 4. Écoute sur le port fourni en CLI (plus besoin de match sur Command)
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", cli.port).parse()?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", cli.port).parse()?;
    swarm.listen_on(tcp_addr)?;
    swarm.listen_on(quic_addr)?;

    // Déclare les adresses externes fournies par l'opérateur : sans ça, le
    // relay n'a aucune adresse confirmée à inclure dans ses réservations de
    // circuit (voir doc du flag `--external-address`).
    for addr in cli.external_address {
        println!("Adresse externe déclarée : {addr}");
        swarm.add_external_address(addr);
    }

    let metrics = Arc::new(metrics::Metrics::default());
    spawn_metrics_writer(Arc::clone(&metrics));
    spawn_readiness_heartbeat("/tmp/nux-ready");

    // 5. Boucle d'événements
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Écoute sur : {address}/p2p/{local_peer_id}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Connexion établie avec {peer_id}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("Connexion fermée avec {peer_id}");
            }
            SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(event)) => {
                match &event {
                    relay::Event::ReservationReqAccepted { .. } => {
                        metrics.record_reservation_accepted();
                    }
                    relay::Event::ReservationReqDenied { .. } => {
                        metrics.record_reservation_denied();
                    }
                    relay::Event::ReservationTimedOut { .. } => {
                        metrics.record_reservation_expired();
                    }
                    relay::Event::CircuitReqAccepted { .. } => {
                        metrics.record_circuit_opened();
                    }
                    relay::Event::CircuitClosed { .. } => {
                        metrics.record_circuit_closed();
                    }
                    // Échecs internes (erreur d'envoi de la réponse, etc.),
                    // distincts d'un refus métier : journalisés, mais aucun
                    // compteur d'exposition dédié pour l'instant.
                    _ => {}
                }
                println!("Relay event: {event:?}");
            }
            SwarmEvent::Behaviour(RelayServerBehaviourEvent::Identify(event)) => {
                println!("Identify event: {event:?}");
            }
            SwarmEvent::Behaviour(RelayServerBehaviourEvent::Rendezvous(event)) => {
                println!("Rendezvous event: {event:?}");
            }
            _ => {}
        }
    }
}
