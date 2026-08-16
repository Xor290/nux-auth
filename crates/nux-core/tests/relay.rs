//! Intégration Phase 7 : traversée de NAT — réservation de circuit relay
//! côté Guard et handshake `/nux/auth/1.0.0` authentifié au travers d'une
//! connexion relayée (`/p2p-circuit`), sans toucher au protocole applicatif.

use nux_core::{
    NuxBehaviourEvent, NuxNodeBuilder, GuardAuthenticator, NodeMode, Whitelist, identity,
};
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, SwarmBuilder, noise, relay, tcp, yamux};
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay minimal (serveur circuit relay v2), miroir en mémoire de
/// `nodes_relay` : accepte les réservations et relaie le trafic entre pairs.
/// Nux ne compose jamais `relay::Behaviour` côté serveur — c'est le rôle
/// exclusif du binaire `nux-relay` — d'où un swarm construit directement
/// ici plutôt que via `NuxNodeBuilder`.
async fn spawn_relay() -> (PeerId, Multiaddr) {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("transport tcp")
        .with_behaviour(|key| {
            relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default())
        })
        .expect("comportement relay")
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .expect("écoute du relay");
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    // Sans `identify::Behaviour` (le vrai `nux-relay` en compose un), le
    // relay n'a aucune adresse externe confirmée à inclure dans ses
    // réservations — le client échoue alors avec `NoAddressesInReservation`.
    // On l'enregistre directement : équivalent, pour ce test, à une adresse
    // observée et confirmée.
    swarm.add_external_address(addr.clone());
    let peer_id = *swarm.local_peer_id();
    tokio::spawn(async move {
        loop {
            swarm.select_next_some().await;
        }
    });
    (peer_id, addr)
}

#[tokio::test]
async fn handshake_succeeds_over_relayed_circuit() {
    let (relay_peer, relay_addr) = spawn_relay().await;

    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["ops"]);

    let guard_keypair = identity::generate();
    let guard_peer = guard_keypair.public().to_peer_id();
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .identity(guard_keypair)
        .build()
        .expect("construction du Guard");

    // Adresse du relay portant son `PeerId` — indispensable pour composer
    // une adresse `/p2p-circuit` valide (réservation comme dial au travers).
    let relay_addr = relay_addr.with(Protocol::P2p(relay_peer));

    // Le Guard doit être connecté au relay avant de pouvoir y réserver un
    // circuit : la réservation transite par cette connexion.
    guard.dial(relay_addr.clone()).expect("dial du relay");
    let connected = tokio::time::timeout(TEST_TIMEOUT, guard.next_connection())
        .await
        .expect("connexion au relay avant le délai")
        .expect("connexion au relay");
    assert_eq!(connected, relay_peer);

    guard
        .listen_on(relay_addr.clone().with(Protocol::P2pCircuit))
        .expect("demande de réservation de circuit");

    // Attend la confirmation de réservation avant de laisser le Client
    // dialer le circuit — sinon la demande côté Client arriverait trop tôt.
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if let SwarmEvent::Behaviour(NuxBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) = guard.next_event().await
            {
                return;
            }
        }
    })
    .await
    .expect("réservation de circuit acceptée avant le délai");

    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard.run_guard(&mut authenticator).await;
    });

    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .build()
        .expect("construction du Client");
    let circuit_addr = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(guard_peer));
    client.dial(circuit_addr).expect("dial du circuit relayé");
    // La première connexion établie est celle vers le relay lui-même (saut
    // intermédiaire) ; `wait_for_peer` attend spécifiquement le circuit vers
    // le Guard plutôt que de faire confiance à la première connexion venue.
    tokio::time::timeout(TEST_TIMEOUT, client.wait_for_peer(guard_peer))
        .await
        .expect("connexion relayée au Guard avant le délai")
        .expect("connexion relayée au Guard");

    let roles = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("l'authentification doit réussir au travers du circuit");
    assert_eq!(roles, vec!["ops".to_string()]);

    guard_task.abort();
}
