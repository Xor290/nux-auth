//! Démon en ligne de commande Nux-Auth.
//!
//! Génération d'identité (`keygen`), Guard protégeant des services locaux
//! derrière liste blanche et rôles (`guard --config guard.toml`), Client
//! redirigeant des ports locaux à travers des tunnels authentifiés
//! (`client --dial --forward`).

use clap::{Parser, Subcommand};
use libp2p::PeerId;
use libp2p::multiaddr::Protocol;
use nux_core::{
    GuardAuthenticator, GuardControl, Multiaddr, Namespace, NodeMode, NuxError, NuxNodeBuilder,
    TunnelRegistry, identity, tunnel,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
mod guard_config;
/// Variable d'environnement standard portant la clé d'identité (hexadécimal).
const IDENTITY_ENV_VAR: &str = "NUX_IDENTITY_KEY";

/// Délai d'inactivité des connexions du démon. Volontairement long : entre
/// deux usages d'un tunnel, la connexion (et donc la session authentifiée,
/// close à la déconnexion) doit survivre. La re-authentification automatique
/// après coupure arrive en phase suivante.
const DAEMON_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Parser)]
#[command(
    name = "nux",
    version,
    about = "Tunnels P2P chiffrés et authentifiés, sans VPN"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Génère une identité Ed25519 et l'écrit dans un fichier (0600).
    Keygen {
        /// Chemin du fichier de clé à créer (refusé s'il existe déjà).
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Démarre un nœud Guard : écoute et protège une ressource locale.
    ///
    /// Toute la topologie (écoute, liste blanche, services exposés, rate
    /// limiting) vient du fichier de configuration ; seule l'identité reste
    /// un flag séparé, pour ne jamais la coucher dans un fichier
    /// versionnable.
    ///
    /// `kill -HUP <pid>` recharge la **liste blanche** (`[[allow]]`) depuis
    /// ce fichier sans redémarrer le Guard : un pair radié voit sa connexion
    /// coupée immédiatement, les autres ne sont pas affectés. Un fichier
    /// invalide au rechargement est rejeté et journalisé, sans effet sur
    /// l'état courant. `listen`, `rate_limit`, `[[expose]]` et
    /// `[[checksum_bin]]` ne sont, eux, pris en compte qu'au démarrage.
    Guard {
        /// Fichier de configuration TOML (écoute, liste blanche, services
        /// exposés, rate limiting). La liste blanche est rechargeable à
        /// chaud par SIGHUP ; le reste exige un redémarrage.
        #[arg(long)]
        config: PathBuf,
        /// Fichier de clé d'identité ; à défaut, la variable
        /// d'environnement NUX_IDENTITY_KEY est utilisée.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Démarre un nœud Client et compose un Guard distant.
    Client {
        /// Adresse multiaddr du Guard à joindre, ou `discover:<namespace>@<rendezvous_multiaddr>`
        /// pour le retrouver par nom logique auprès d'un point de rendezvous
        /// (voir `namespace` dans `guard.toml`) sans en connaître l'adresse.
        #[arg(long, value_parser = parse_dial_target)]
        dial: DialTarget,
        /// Fichier de clé d'identité ; à défaut, la variable
        /// d'environnement NUX_IDENTITY_KEY est utilisée.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Port local à rediriger, au format `PORT_LOCAL:SERVICE` : écoute
        /// sur 127.0.0.1:PORT_LOCAL, relayé vers le service exposé par le
        /// Guard. **Non authentifié localement** : tout process du système,
        /// quel que soit son utilisateur, peut s'y connecter. Répétable.
        #[arg(long = "forward", value_parser = parse_forward)]
        forward: Vec<ForwardEntry>,
        /// Socket Unix à rediriger, au format `CHEMIN:SERVICE:UID[,UID...]` :
        /// la connexion n'est relayée que si l'UID du process pair — fourni
        /// par le noyau (`SO_PEERCRED`), non falsifiable — figure dans la
        /// liste. Le fichier est créé en `0600` ; le dossier parent doit être
        /// protégé par l'opérateur (`0700`, propriétaire = l'utilisateur
        /// applicatif). Répétable.
        #[cfg(unix)]
        #[arg(long = "forward-unix", value_parser = parse_forward_unix)]
        forward_unix: Vec<ForwardUnixEntry>,
    },
    /// Compagnon de poll : interroge périodiquement `nux_gateway` (à travers
    /// un tunnel `nux client --forward PORT:gwapi-guard` déjà en place) pour
    /// la config de ce Guard, et recharge `guard.toml` + `SIGHUP` le Guard
    /// dès qu'elle change — sans redémarrage, en réutilisant le mécanisme de
    /// rechargement à chaud déjà existant (`GuardControl::ReloadWhitelist`).
    ///
    /// Ne modifie que `[rate_limit]`, `[[allow]]` et `[[checksum_bin]]` dans
    /// `guard.toml` ; `listen`, `[[expose]]`, `relay`, `namespace` et les
    /// commentaires de l'opérateur restent intacts.
    #[cfg(unix)]
    SyncConfig {
        /// Fichier `guard.toml` de ce Guard, à tenir à jour.
        #[arg(long)]
        config: PathBuf,
        /// Port local où `nux client --forward PORT:gwapi-guard` réinjecte
        /// l'API REST de la Gateway.
        #[arg(long)]
        gateway_port: u16,
        /// PeerId de ce Guard — sert de `:uuid` dans `GET /api/v1/configs/:uuid`.
        #[arg(long, value_parser = parse_peer_id)]
        uuid: PeerId,
        /// PID du processus `nux guard` à qui envoyer SIGHUP après réécriture
        /// (ex. `$(pgrep -f 'nux guard')`, comme déjà documenté au README).
        #[arg(long)]
        guard_pid: i32,
        /// Intervalle entre deux vérifications.
        #[arg(long, default_value_t = 30)]
        poll_secs: u64,
    },
}

/// Redirection fournie sur la ligne de commande : port local, service.
type ForwardEntry = (u16, String);

/// Redirection Unix fournie sur la ligne de commande : chemin, service, UID autorisés.
#[cfg(unix)]
type ForwardUnixEntry = (PathBuf, String, Vec<u32>);

/// Analyse `PORT_LOCAL:SERVICE`.
fn parse_forward(value: &str) -> Result<ForwardEntry, String> {
    let (port, service) = value
        .split_once(':')
        .ok_or_else(|| "format attendu: PORT_LOCAL:SERVICE".to_string())?;
    let port = port
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("port local invalide: {e}"))?;
    let service = service.trim();
    if service.is_empty() {
        return Err("nom de service vide (format: PORT_LOCAL:SERVICE)".to_string());
    }
    Ok((port, service.to_owned()))
}

/// Analyse `CHEMIN:SERVICE:UID[,UID...]`.
#[cfg(unix)]
fn parse_forward_unix(value: &str) -> Result<ForwardUnixEntry, String> {
    let mut parts = value.splitn(3, ':');
    let path = parts
        .next()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            "chemin de socket manquant (format: CHEMIN:SERVICE:UID[,UID...])".to_string()
        })?;
    let service = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "nom de service manquant (format: CHEMIN:SERVICE:UID[,UID...])".to_string()
        })?;
    let uids_raw = parts.next().ok_or_else(|| {
        "UID autorisé(s) manquant(s) (format: CHEMIN:SERVICE:UID[,UID...])".to_string()
    })?;
    let uids = uids_raw
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(|u| {
            u.parse::<u32>()
                .map_err(|e| format!("UID invalide `{u}`: {e}"))
        })
        .collect::<Result<Vec<u32>, String>>()?;
    if uids.is_empty() {
        return Err("au moins un UID doit être autorisé (une liste vide refuse tout)".to_string());
    }
    Ok((PathBuf::from(path), service.to_owned(), uids))
}

/// Cible d'un `--dial` : soit une adresse directe (multiaddr habituelle,
/// éventuellement `/p2p-circuit`), soit une découverte par nom logique
/// auprès d'un point de rendezvous.
#[derive(Clone)]
enum DialTarget {
    Address(Multiaddr),
    Discover {
        namespace: String,
        rendezvous: Multiaddr,
    },
}

/// Analyse `--dial` : soit une multiaddr classique, soit
/// `discover:<namespace>@<rendezvous_multiaddr>`.
fn parse_dial_target(value: &str) -> Result<DialTarget, String> {
    match value.strip_prefix("discover:") {
        Some(rest) => {
            let (namespace, rendezvous) = rest.split_once('@').ok_or_else(|| {
                "format attendu: discover:<namespace>@<rendezvous_multiaddr>".to_string()
            })?;
            if namespace.is_empty() {
                return Err(
                    "namespace vide (format: discover:<namespace>@<rendezvous_multiaddr>)"
                        .to_string(),
                );
            }
            let rendezvous = rendezvous
                .parse::<Multiaddr>()
                .map_err(|e| format!("adresse de rendezvous invalide: {e}"))?;
            Ok(DialTarget::Discover {
                namespace: namespace.to_owned(),
                rendezvous,
            })
        }
        None => value
            .parse::<Multiaddr>()
            .map(DialTarget::Address)
            .map_err(|e| format!("multiaddr invalide: {e}")),
    }
}

/// Analyse un `PeerId` en base58 (ex. `--uuid` de `sync-config`).
#[cfg(unix)]
fn parse_peer_id(value: &str) -> Result<PeerId, String> {
    value
        .parse::<PeerId>()
        .map_err(|e| format!("PeerId invalide: {e}"))
}

/// Dernier composant `/p2p/<peer>` d'une adresse, s'il y en a un — c'est le
/// pair effectivement visé par le dial, qu'il s'agisse d'une adresse directe
/// ou d'un circuit relay (`.../p2p-circuit/p2p/<cible>`).
fn target_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter()
        .filter_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .last()
}

/// Prépare un builder avec le mode et la source d'identité demandés.
fn builder(mode: NodeMode, identity: Option<PathBuf>) -> NuxNodeBuilder {
    let builder = NuxNodeBuilder::new()
        .mode(mode)
        .idle_timeout(DAEMON_IDLE_TIMEOUT);
    match identity {
        Some(path) => builder.identity_file(path),
        None if std::env::var_os(IDENTITY_ENV_VAR).is_some() => {
            builder.identity_env(IDENTITY_ENV_VAR)
        }
        // Sans identité fournie, le nœud démarre avec une clé éphémère :
        // pratique pour les essais, inutilisable face à une liste blanche.
        None => builder,
    }
}

/// Écoute `SIGHUP` et recharge la liste blanche depuis `config_path` à
/// chaque réception : `kill -HUP <pid>` (ou `systemctl reload`) prend alors
/// effet sans redémarrer le Guard ni couper les tunnels des pairs qui
/// restent autorisés. Un fichier invalide au rechargement est rejeté et
/// journalisé, **sans aucun effet** sur l'état courant — le Guard continue
/// de servir avec la configuration précédente plutôt que de basculer dans un
/// état partiel.
#[cfg(unix)]
fn spawn_reload_on_sighup(
    config_path: PathBuf,
    control_tx: tokio::sync::mpsc::Sender<GuardControl>,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(sig) => sig,
        Err(e) => {
            warn!(error = %e, "écoute de SIGHUP indisponible: rechargement à chaud désactivé");
            return;
        }
    };
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match guard_config::load(&config_path) {
                Ok(cfg) => {
                    info!(
                        config = %config_path.display(),
                        "SIGHUP reçu: rechargement de la liste blanche"
                    );
                    if control_tx
                        .send(GuardControl::ReloadWhitelist(cfg.whitelist))
                        .await
                        .is_err()
                    {
                        break; // le Guard s'est arrêté : plus personne pour consommer.
                    }
                }
                Err(e) => {
                    warn!(
                        config = %config_path.display(),
                        error = %e,
                        "SIGHUP reçu: rechargement refusé, configuration précédente conservée"
                    );
                }
            }
        }
    });
}

/// Envoie `SIGHUP` à `pid` — même effet que `kill -HUP <pid>` en ligne de
/// commande, déclenchant le rechargement à chaud déjà câblé côté Guard
/// ([`spawn_reload_on_sighup`]).
#[cfg(unix)]
fn send_sighup(pid: i32) -> nux_core::Result<()> {
    let pid = rustix::process::Pid::from_raw(pid)
        .ok_or_else(|| NuxError::Config(format!("PID invalide: {pid}")))?;
    rustix::process::kill_process(pid, rustix::process::Signal::Hup)
        .map_err(|e| NuxError::Config(format!("envoi de SIGHUP à {pid:?}: {e}")))
}

/// Récupère la config de ce Guard auprès de `nux_gateway`, à travers le
/// tunnel déjà forwardé sur `127.0.0.1:gateway_port` (voir `nux client
/// --forward PORT:gwapi-guard`). Ne fait aucune hypothèse sur la fraîcheur du
/// tunnel : chaque appel est une requête HTTP normale, bornée dans le temps.
#[cfg(unix)]
async fn fetch_remote_config(
    http: &reqwest::Client,
    gateway_port: u16,
    uuid: PeerId,
) -> nux_core::Result<guard_config::RemoteConfig> {
    let url = format!("http://127.0.0.1:{gateway_port}/api/v1/private/configs/{uuid}");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| NuxError::Network(format!("Gateway injoignable ({url}): {e}")))?;
    if !resp.status().is_success() {
        return Err(NuxError::Network(format!(
            "Gateway a répondu {} pour {url}",
            resp.status()
        )));
    }
    resp.json::<guard_config::RemoteConfig>()
        .await
        .map_err(|e| NuxError::Network(format!("réponse Gateway invalide: {e}")))
}

/// Boucle de `sync-config` : interroge la Gateway toutes les `poll_interval`,
/// et seulement si `updated_at` a changé depuis le dernier passage, réécrit
/// `config_path` puis envoie `SIGHUP` à `guard_pid` — silencieux (hors logs)
/// le reste du temps, pour ne pas produire un rechargement (et une entrée de
/// journal) à chaque cycle alors que rien n'a changé.
#[cfg(unix)]
async fn sync_config_loop(
    config_path: PathBuf,
    gateway_port: u16,
    uuid: PeerId,
    guard_pid: i32,
    poll_interval: Duration,
) -> nux_core::Result<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| NuxError::Config(format!("client HTTP: {e}")))?;
    let mut last_updated_at: Option<String> = None;
    info!(gateway_port, %uuid, guard_pid, ?poll_interval, "sync-config démarré");

    loop {
        match fetch_remote_config(&http, gateway_port, uuid).await {
            Ok(remote) if last_updated_at.as_deref() == Some(remote.updated_at.as_str()) => {
                tracing::debug!(updated_at = %remote.updated_at, "config Gateway inchangée");
            }
            Ok(remote) => match guard_config::apply_remote_config(&config_path, &remote) {
                Ok(()) => {
                    info!(
                        config = %config_path.display(),
                        updated_at = %remote.updated_at,
                        "config Gateway appliquée, SIGHUP envoyé au Guard"
                    );
                    last_updated_at = Some(remote.updated_at.clone());
                    if let Err(e) = send_sighup(guard_pid) {
                        warn!(error = %e, "SIGHUP non envoyé au Guard");
                    }
                }
                Err(e) => warn!(
                    config = %config_path.display(),
                    error = %e,
                    "réécriture de guard.toml refusée, configuration précédente conservée"
                ),
            },
            Err(e) => warn!(error = %e, "récupération de la config Gateway échouée"),
        }

        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = wait_for_shutdown_signal() => {
                info!("signal d'arrêt reçu: sync-config arrêté");
                return Ok(());
            }
        }
    }
}

/// Délai de grâce par défaut avant qu'un arrêt gracieux ne coupe de force les
/// tunnels/relais encore actifs.
const DEFAULT_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Attend un signal d'arrêt : `Ctrl-C` partout, `SIGTERM` en plus sous Unix
/// (c'est le signal envoyé par `systemctl stop`/`docker stop`).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "écoute de SIGTERM indisponible: seul Ctrl-C déclenchera l'arrêt gracieux");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `None` si le journal d'audit n'a pas pu être ouvert (répertoire absent ou
/// non inscriptible) : dégradé plutôt que fatal — un souci de journalisation
/// ne doit jamais empêcher le démon de démarrer. Le journal applicatif
/// (stderr) reste actif dans tous les cas.
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

    let audit_dir =
        std::env::var("NUX_AUDIT_LOG_DIR").unwrap_or_else(|_| "/var/log/nux".to_string());
    let audit_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("audit")
        .filename_suffix("jsonl")
        .build(&audit_dir);

    let (audit_layer, audit_guard) = match audit_appender {
        Ok(audit_file) => {
            let (audit_writer, audit_guard) = tracing_appender::non_blocking(audit_file);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(audit_writer)
                .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target() == "nux::audit"
                }));
            (Some(layer), Some(audit_guard))
        }
        Err(e) => {
            eprintln!(
                "journal d'audit indisponible ({audit_dir}: {e}) : \
                 NUX_AUDIT_LOG_DIR doit pointer vers un répertoire inscriptible ; \
                 poursuite sans journal d'audit dédié"
            );
            (None, None)
        }
    };

    let app_layer = tracing_subscriber::fmt::layer()
        .with_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,nux=debug".into()))
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target() != "nux::audit"
        }));

    tracing_subscriber::registry()
        .with(app_layer)
        .with(audit_layer)
        .init();

    audit_guard
}
pub fn spawn_metrics_writer(metrics: Arc<nux_core::metrics::Metrics>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let tmp = "/var/lib/node_exporter/textfile_collector/nux.prom.tmp";
            let dest = "/var/lib/node_exporter/textfile_collector/nux.prom";
            if tokio::fs::write(tmp, metrics.to_prometheus_text())
                .await
                .is_ok()
            {
                let _ = tokio::fs::rename(tmp, dest).await; // écriture atomique
            }
        }
    });
}
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
async fn main() -> nux_core::Result<()> {
    // Charge un éventuel fichier .env dans l'environnement du processus, en
    // silence et sans échec s'il est absent : simple confort pour renseigner
    // NUX_IDENTITY_KEY en local. Le contenu n'est ni lu ni journalisé ici —
    // c'est `identity::from_env` (Zeroizing) qui le consomme, jamais exposé.
    dotenvy::dotenv().ok();

    // Durcissement anti-ptrace avant toute manipulation de clé (best-effort :
    // défense en profondeur, ne doit pas empêcher le démarrage). La clé étant
    // chargée juste après, on se rend non-dumpable dès maintenant.
    let _audit_guard = init_tracing();

    match nux_core::hardening::harden_process() {
        Ok(()) => tracing::debug!("processus durci (non-dumpable, anti-ptrace)"),
        Err(e) => warn!(error = %e, "durcissement anti-ptrace indisponible"),
    }

    match Cli::parse().command {
        Command::Keygen { out } => {
            let keypair = identity::generate();
            identity::save_to_file(&keypair, &out)?;
            println!("Clé écrite dans {} (0600)", out.display());
            println!(
                "PeerId (à inscrire en liste blanche): {}",
                keypair.public().to_peer_id()
            );
        }
        Command::Guard { config, identity } => {
            let cfg = guard_config::load(&config)?;
            let mut guard_builder = builder(NodeMode::Guard, identity)
                .listen_on(cfg.listen)
                .inbound_rate_limit(cfg.rate_limit_max, cfg.rate_limit_window);
            for ip in cfg.rate_limit_exempt {
                info!(%ip, "IP exemptée du rate limiting");
                guard_builder = guard_builder.rate_limit_exempt(ip);
            }

            let mut node = guard_builder.build()?;
            if cfg.whitelist.is_empty() {
                warn!("liste blanche vide: tout pair entrant sera coupé en silence");
            }
            if let Some(relay_addr) = cfg.relay {
                info!(%relay_addr, "connexion au relay pour réservation de circuit");
                // Un échec ici (relay injoignable, délai dépassé, protocole
                // non supporté) n'empêche pas le Guard de démarrer : il reste
                // joignable sur ses adresses d'écoute directes, seule la voie
                // relayée (et l'éventuel enregistrement rendezvous, qui en
                // dépend) est indisponible. La réservation elle-même exige
                // une connexion déjà établie au relay — on l'attend d'abord,
                // borné, plutôt que de risquer une demande émise trop tôt.
                const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
                node.dial(relay_addr.clone())?;
                match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, node.next_connection()).await {
                    Ok(Ok(relay_peer)) => {
                        let reserved = match node
                            .listen_on(relay_addr.clone().with(Protocol::P2pCircuit))
                        {
                            Ok(()) => {
                                // `listen_on` ne fait que mettre la demande en
                                // file : l'adresse `/p2p-circuit` n'est
                                // confirmée externe (condition requise par
                                // `register_namespace`) qu'à réception de cet
                                // événement.
                                match tokio::time::timeout(
                                    RELAY_CONNECT_TIMEOUT,
                                    node.wait_for_circuit_reservation(relay_peer),
                                )
                                .await
                                {
                                    Ok(Ok(())) => true,
                                    Ok(Err(e)) => {
                                        warn!(%relay_addr, error = %e, "réservation de circuit refusée");
                                        false
                                    }
                                    Err(_) => {
                                        warn!(%relay_addr, "réservation de circuit non confirmée (délai dépassé)");
                                        false
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(%relay_addr, error = %e, "réservation de circuit refusée");
                                false
                            }
                        };
                        if let Some(namespace) = cfg.namespace {
                            if !reserved {
                                warn!(%namespace, "enregistrement rendezvous ignoré: pas de réservation de circuit confirmée");
                            } else {
                                info!(%namespace, "enregistrement auprès du point de rendezvous");
                                match node.register_namespace(relay_peer, namespace.clone()).await {
                                    Ok(()) => {
                                        info!(%namespace, "enregistrement rendezvous accepté")
                                    }
                                    Err(e) => {
                                        warn!(%namespace, error = %e, "enregistrement rendezvous refusé")
                                    }
                                }
                            }
                        }
                    }

                    Ok(Err(e)) => {
                        warn!(%relay_addr, error = %e, "relay injoignable: circuit non réservé");
                    }
                    Err(_) => {
                        warn!(%relay_addr, "relay injoignable (délai dépassé): circuit non réservé");
                    }
                }
            }
            let mut registry = TunnelRegistry::new();
            for (name, port, role) in cfg.expose {
                info!(service = %name, port, role = ?role, "service exposé");
                registry.expose(name, SocketAddr::from((Ipv4Addr::LOCALHOST, port)), role);
            }
            for (peer, sha256) in cfg.checksum_bin {
                info!(%peer, "empreinte de binaire attendue enregistrée");
                registry.require_binary_sha256(peer, sha256);
            }
            let mut authenticator = GuardAuthenticator::new(cfg.whitelist);
            info!(peer_id = %node.local_peer_id(), "Guard démarré");

            let (control_tx, control_rx) = tokio::sync::mpsc::channel(8);
            #[cfg(unix)]
            spawn_reload_on_sighup(config, control_tx.clone());

            // Le drainage (silence radio sur les nouvelles authentifications/
            // tunnels, tunnels en cours laissés le temps de se terminer) est
            // entièrement piloté par `run_guard_with_control` lui-même — ce
            // canal ne fait que relayer la demande, exactement comme SIGHUP.
            tokio::spawn(async move {
                wait_for_shutdown_signal().await;
                info!(
                    grace_period = ?DEFAULT_SHUTDOWN_GRACE_PERIOD,
                    "signal d'arrêt reçu: arrêt gracieux du Guard"
                );
                let _ = control_tx
                    .send(GuardControl::Shutdown {
                        grace_period: DEFAULT_SHUTDOWN_GRACE_PERIOD,
                    })
                    .await;
            });
            spawn_metrics_writer(node.metrics());
            spawn_readiness_heartbeat("/etc/nux/nux-ready");
            node.run_guard_with_control(&mut authenticator, registry, control_rx)
                .await;
            info!("Guard arrêté");
        }
        Command::Client {
            dial,
            identity,
            forward,
            #[cfg(unix)]
            forward_unix,
        } => {
            let mut node = builder(NodeMode::Client, identity).build()?;
            // `guard_addr` sert à la reconnexion (`run_client_session`) : en
            // découverte, c'est l'adresse effectivement jointe qui est
            // rejouée en cas de coupure — pas une nouvelle découverte.
            let (guard_peer, guard_addr) = match dial {
                DialTarget::Address(addr) => {
                    node.dial(addr.clone())?;
                    // Une adresse `/p2p-circuit` nomme explicitement le pair
                    // visé en dernier composant `/p2p/<peer>` : la première
                    // connexion établie est alors celle vers le relay (saut
                    // intermédiaire), pas vers ce pair — il faut l'attendre
                    // spécifiquement plutôt que de faire confiance à la
                    // première connexion venue.
                    let peer = match target_peer_id(&addr) {
                        Some(target) => {
                            node.wait_for_peer(target).await?;
                            target
                        }
                        None => node.next_connection().await?,
                    };
                    (peer, addr)
                }
                DialTarget::Discover {
                    namespace,
                    rendezvous,
                } => {
                    let rendezvous_peer = target_peer_id(&rendezvous).ok_or_else(|| {
                        NuxError::Config(
                            "adresse de rendezvous invalide: doit inclure /p2p/<peer_id>".into(),
                        )
                    })?;
                    let namespace = Namespace::new(namespace.clone()).map_err(|_| {
                        NuxError::Config(format!("namespace `{namespace}` invalide: trop long"))
                    })?;
                    node.dial(rendezvous.clone())?;
                    node.wait_for_peer(rendezvous_peer).await?;
                    info!(%namespace, %rendezvous_peer, "découverte de pair par namespace");
                    node.discover_and_dial(rendezvous_peer, namespace).await?
                }
            };
            let roles = node.authenticate(&guard_peer).await?;
            info!(%guard_peer, ?roles, "authentifié auprès du Guard");
            spawn_metrics_writer(node.metrics());
            spawn_readiness_heartbeat("/etc/nux/nux-ready");
            // Un seul jeton partagé par toutes les redirections locales et la
            // session : sur signal d'arrêt, chacune cesse d'accepter de
            // nouvelles connexions et draine ses relais en cours pendant que
            // `run_client_session` maintient le swarm actif pour elles.
            let shutdown = tokio_util::sync::CancellationToken::new();
            tokio::spawn({
                let shutdown = shutdown.clone();
                async move {
                    wait_for_shutdown_signal().await;
                    info!(
                        grace_period = ?DEFAULT_SHUTDOWN_GRACE_PERIOD,
                        "signal d'arrêt reçu: arrêt gracieux du Client"
                    );
                    shutdown.cancel();
                }
            });

            for (port, service) in forward {
                let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
                warn!(
                    port,
                    service,
                    "port TCP local redirigé (non authentifié : tout process local peut s'y connecter)"
                );
                tokio::spawn(tunnel::forward_listener(
                    node.tunnel_control(),
                    guard_peer,
                    service,
                    listener,
                    shutdown.clone(),
                    DEFAULT_SHUTDOWN_GRACE_PERIOD,
                ));
            }
            #[cfg(unix)]
            for (path, service, allowed_uids) in forward_unix {
                let listener = tunnel::bind_forward_socket(&path)?;
                info!(path = %path.display(), service, ?allowed_uids, "socket Unix locale redirigée");
                tokio::spawn(tunnel::forward_unix_listener(
                    node.tunnel_control(),
                    guard_peer,
                    service,
                    listener,
                    allowed_uids,
                    shutdown.clone(),
                    DEFAULT_SHUTDOWN_GRACE_PERIOD,
                ));
            }

            info!(peer_id = %node.local_peer_id(), mode = ?node.mode(), "nœud démarré");
            // Boucle résiliente : si la connexion au Guard tombe, recompose
            // et rejoue le handshake ; les redirections ci-dessus survivent.
            node.run_client_session(
                guard_peer,
                guard_addr,
                shutdown,
                DEFAULT_SHUTDOWN_GRACE_PERIOD,
            )
            .await;
            info!("Client arrêté");
        }
        #[cfg(unix)]
        Command::SyncConfig {
            config,
            gateway_port,
            uuid,
            guard_pid,
            poll_secs,
        } => {
            sync_config_loop(
                config,
                gateway_port,
                uuid,
                guard_pid,
                Duration::from_secs(poll_secs),
            )
            .await?;
        }
    }
    Ok(())
}
