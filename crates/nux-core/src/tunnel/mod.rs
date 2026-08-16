//! Tunneling TCP pair-à-pair (Phase 3, cadrage §2.2).
//!
//! Un Client intercepte des connexions TCP locales et les relaie, via un flux
//! Yamux dédié `/nux/tunnel/1.0.0` chiffré de bout en bout par Noise,
//! jusqu'au Guard qui les réinjecte vers le service local exposé
//! (`127.0.0.1` distant).
//!
//! Déroulé d'une ouverture :
//! 1. le Client ouvre un flux et envoie un en-tête
//!    [`TunnelHeader`](crate::protocol::TunnelHeader) — le nom logique du
//!    service demandé, trame bornée à
//!    [`MAX_TUNNEL_HEADER_SIZE`](crate::protocol::MAX_TUNNEL_HEADER_SIZE) ;
//! 2. le Guard n'examine l'en-tête que si le pair possède une session
//!    authentifiée (Phase 2) ; il vérifie ensuite que le service est exposé
//!    dans sa [`TunnelRegistry`] et que la session détient le rôle requis
//!    (comparaison en temps constant) ;
//! 3. en cas de succès, le Guard se connecte au service local, acquitte d'un
//!    octet [`TUNNEL_ACK`](crate::protocol::TUNNEL_ACK) puis relaie les
//!    octets dans les deux sens ;
//! 4. toute anomalie — pair sans session, service inconnu, rôle manquant,
//!    empreinte de binaire inattendue, en-tête illisible ou tardif —
//!    abandonne le flux **sans un octet de réponse** (silence radio, cadrage
//!    §3.3) ; le motif reste dans les journaux locaux du Guard.

use crate::attestation::{self, SHA256_LEN};
use crate::error::NuxError;
use crate::protocol::{self, MAX_TUNNEL_HEADER_SIZE, TUNNEL_ACK, TUNNEL_PROTOCOL, TunnelHeader};
use constant_time_eq::constant_time_eq;
use libp2p::PeerId;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub use libp2p_stream::{Control, OpenStreamError};

/// Délai accordé au pair pour transmettre son en-tête après l'ouverture du
/// flux : au-delà, le Guard abandonne pour ne pas retenir de ressources.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Flux tunnel établi, adapté à l'écosystème tokio (`AsyncRead`/`AsyncWrite`).
pub type TunnelStream = Compat<libp2p::Stream>;

/// Service local exposé par un Guard.
struct ExposedService {
    /// Adresse de réinjection (typiquement `127.0.0.1:port`).
    target: SocketAddr,
    /// Rôle exigé de la session ; `None` admet tout pair authentifié.
    required_role: Option<String>,
}

/// Plafond par défaut de flux tunnel concurrents pour un même pair.
pub const DEFAULT_MAX_STREAMS_PER_PEER: usize = 64;
/// Plafond par défaut de flux tunnel concurrents tous pairs confondus.
pub const DEFAULT_MAX_STREAMS_TOTAL: usize = 1024;

/// Table des services qu'un Guard accepte de tunneliser.
///
/// Un service est désigné par un nom logique (côté Client) et résolu vers une
/// adresse locale (côté Guard) : l'adresse réelle du service ne circule
/// jamais sur le réseau.
///
/// La table porte aussi les plafonds anti-amplification : un pair authentifié
/// pourrait sinon ouvrir un nombre illimité de flux Yamux, chacun ouvrant une
/// connexion TCP vers le service local, et épuiser le backend (pool de
/// connexions, descripteurs). Au-delà du plafond, le flux excédentaire est
/// abandonné en silence.
pub struct TunnelRegistry {
    services: HashMap<String, ExposedService>,
    max_streams_per_peer: usize,
    max_streams_total: usize,
    /// Empreintes SHA-256 de binaire attendues, par pair (Phase 5,
    /// attestation logicielle — voir [`crate::attestation`]). Un pair absent
    /// de cette table n'est soumis à aucun contrôle d'empreinte.
    attested_binaries: HashMap<PeerId, [u8; SHA256_LEN]>,
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            services: HashMap::new(),
            max_streams_per_peer: DEFAULT_MAX_STREAMS_PER_PEER,
            max_streams_total: DEFAULT_MAX_STREAMS_TOTAL,
            attested_binaries: HashMap::new(),
        }
    }
}

impl TunnelRegistry {
    /// Table vide : tout flux tunnel entrant sera abandonné.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajuste les plafonds de flux tunnel concurrents (par pair, puis
    /// globalement). Un `0` interdit tout tunnel.
    pub fn max_concurrent_streams(&mut self, per_peer: usize, total: usize) -> &mut Self {
        self.max_streams_per_peer = per_peer;
        self.max_streams_total = total;
        self
    }

    /// Plafond de flux concurrents pour un même pair.
    pub fn max_streams_per_peer(&self) -> usize {
        self.max_streams_per_peer
    }

    /// Plafond de flux concurrents tous pairs confondus.
    pub fn max_streams_total(&self) -> usize {
        self.max_streams_total
    }

    /// Expose le service `name` vers l'adresse locale `target`.
    /// `required_role` restreint l'accès aux sessions détenant ce rôle ;
    /// `None` admet tout pair authentifié.
    pub fn expose(
        &mut self,
        name: impl Into<String>,
        target: SocketAddr,
        required_role: Option<String>,
    ) -> &mut Self {
        self.services.insert(
            name.into(),
            ExposedService {
                target,
                required_role,
            },
        );
        self
    }

    /// Nombre de services exposés.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// `true` si aucun service n'est exposé.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    fn get(&self, name: &str) -> Option<&ExposedService> {
        self.services.get(name)
    }

    /// Enregistre l'empreinte SHA-256 de binaire attendue pour `peer`
    /// (attestation logicielle, Phase 5). À l'ouverture d'un tunnel, une
    /// empreinte déclarée qui ne correspond pas abandonne le flux sans un
    /// octet, au même titre qu'un rôle manquant.
    ///
    /// Comme documenté dans [`crate::attestation`], ce contrôle est
    /// best-effort : le Client déclare lui-même son empreinte. Un pair non
    /// enregistré ici n'est soumis à aucun contrôle (opt-in par pair).
    pub fn require_binary_sha256(&mut self, peer: PeerId, sha256: [u8; SHA256_LEN]) -> &mut Self {
        self.attested_binaries.insert(peer, sha256);
        self
    }

    fn expected_binary_sha256(&self, peer: &PeerId) -> Option<[u8; SHA256_LEN]> {
        self.attested_binaries.get(peer).copied()
    }
}

/// Vérifie qu'un rôle requis figure dans les rôles de session. Parcours
/// complet sans sortie anticipée et comparaisons `constant_time_eq`, à
/// l'image de [`crate::Whitelist`] : le temps de réponse ne renseigne ni sur
/// la présence du rôle ni sur sa position.
fn role_granted(granted: &[String], required: Option<&str>) -> bool {
    let Some(required) = required else {
        return true;
    };
    let mut authorized = false;
    for role in granted {
        let matches =
            role.len() == required.len() && constant_time_eq(role.as_bytes(), required.as_bytes());
        if matches {
            authorized = true;
        }
    }
    authorized
}

/// Écrit l'en-tête d'ouverture : longueur `u16` gros-boutiste puis bincode.
async fn write_header<S>(stream: &mut S, header: &TunnelHeader) -> crate::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = protocol::encode(header)?;
    let len = u16::try_from(bytes.len())
        .ok()
        .filter(|len| usize::from(*len) <= MAX_TUNNEL_HEADER_SIZE)
        .ok_or_else(|| {
            NuxError::Tunnel(format!(
                "en-tête de tunnel trop long ({} octets, max {MAX_TUNNEL_HEADER_SIZE})",
                bytes.len()
            ))
        })?;
    stream.write_u16(len).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Lit et décode l'en-tête d'ouverture, en refusant toute trame plus grosse
/// que [`MAX_TUNNEL_HEADER_SIZE`] avant même de la lire.
async fn read_header<S>(stream: &mut S) -> io::Result<TunnelHeader>
where
    S: AsyncRead + Unpin,
{
    let len = usize::from(stream.read_u16().await?);
    if len > MAX_TUNNEL_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "en-tête de tunnel trop long",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    protocol::decode(&buf)
}

/// Côté Client : ouvre un tunnel vers `service` auprès d'un Guard connecté
/// et authentifié, et retourne le flux prêt à relayer une fois
/// l'acquittement reçu.
///
/// Un refus — pair non authentifié, service inconnu, rôle manquant — se
/// manifeste par une coupure sèche du flux (silence radio du Guard) et
/// produit [`NuxError::AccessDenied`], sans motif exploitable. Le swarm du
/// nœud doit être piloté en parallèle pour que l'ouverture aboutisse.
pub async fn open(
    control: &mut Control,
    guard: PeerId,
    service: &str,
) -> crate::Result<TunnelStream> {
    let stream = control
        .open_stream(guard, TUNNEL_PROTOCOL)
        .await
        .map_err(|e| NuxError::Tunnel(e.to_string()))?;
    let mut stream = stream.compat();
    write_header(
        &mut stream,
        &TunnelHeader {
            service: service.to_owned(),
            binary_sha256: attestation::current_binary_sha256()?,
        },
    )
    .await?;
    let mut ack = [0u8; 1];
    // Le Guard n'émet JAMAIS de refus : une fin de flux ici recouvre tous les
    // motifs possibles, volontairement indistinguables.
    stream
        .read_exact(&mut ack)
        .await
        .map_err(|_| NuxError::AccessDenied)?;
    if ack != [TUNNEL_ACK] {
        return Err(NuxError::Protocol(format!(
            "acquittement de tunnel inattendu: {:#04x}",
            ack[0]
        )));
    }
    Ok(stream)
}

/// Relaie une connexion locale déjà acceptée (TCP ou Unix) à travers un
/// tunnel neuf. Générique sur le type de flux local : seuls comptent
/// `AsyncRead`/`AsyncWrite`. Tout échec est journalisé localement puis la
/// socket locale est refermée — vu du programme client, l'extrémité locale se
/// comporte comme un service qui coupe.
async fn relay_local<S>(mut control: Control, guard: PeerId, service: &str, mut local: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tunnel = match open(&mut control, guard, service).await {
        Ok(tunnel) => tunnel,
        Err(e) => {
            debug!(%guard, service, error = %e, "ouverture de tunnel impossible");
            return;
        }
    };
    match tokio::io::copy_bidirectional(&mut local, &mut tunnel).await {
        Ok((sent, received)) => debug!(%guard, service, sent, received, "tunnel refermé"),
        Err(e) => debug!(%guard, service, error = %e, "tunnel interrompu"),
    }
}

/// Relaie une connexion TCP locale déjà acceptée à travers un tunnel neuf.
/// Tout échec est journalisé localement puis la socket locale est refermée —
/// vu du programme client, le port se comporte comme un service qui coupe.
pub async fn forward_connection(control: Control, guard: PeerId, service: &str, local: TcpStream) {
    relay_local(control, guard, service, local).await;
}

/// Vérifie que l'UID du process pair d'une connexion Unix figure dans la
/// liste blanche. `SO_PEERCRED` fournit un UID **réel et non falsifiable**,
/// imposé par le noyau : c'est la contrepartie locale, côté Client, de
/// l'attestation SHA-256 côté Guard. Un `allowed_uids` vide refuse tout.
#[cfg(unix)]
fn peer_uid_authorized(local: &UnixStream, allowed_uids: &[u32]) -> bool {
    match local.peer_cred() {
        Ok(cred) => allowed_uids.contains(&cred.uid()),
        Err(e) => {
            debug!(error = %e, "credentials du pair local illisibles: connexion refusée");
            false
        }
    }
}

/// Lie une socket Unix pour la redirection locale : retire une socket obsolète
/// au même chemin, lie, puis restreint le fichier à son propriétaire (`0600`).
///
/// Le **dossier parent** doit être protégé par l'opérateur (`0700`,
/// propriétaire = l'utilisateur applicatif) : cela ferme la brève fenêtre
/// entre `bind` et `set_permissions` et empêche un tiers de pré-créer ou de
/// détourner le chemin de la socket.
#[cfg(unix)]
pub fn bind_forward_socket(path: &std::path::Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    // Ne retire qu'une socket obsolète — jamais un fichier régulier ou un lien
    // (on n'efface pas par erreur autre chose que ce qu'on a créé soi-même).
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_socket()
    {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Boucle d'acceptation côté Client sur une **socket Unix** locale. Chaque
/// connexion n'est relayée vers `service` que si l'UID du process qui se
/// connecte — fourni par le noyau via `SO_PEERCRED` — figure dans
/// `allowed_uids` ; sinon elle est fermée sans un octet (silence radio local).
///
/// C'est l'équivalent authentifié de [`forward_listener`] : là où un port TCP
/// loopback accepte n'importe quel process local, la socket Unix impose une
/// double barrière noyau (permissions `0600` du fichier + contrôle d'UID).
///
/// Retourne dès que `shutdown` est déclenché : plus aucune nouvelle connexion
/// locale n'est acceptée, mais les relais déjà en cours ont jusqu'à
/// `grace_period` pour se terminer d'eux-mêmes avant que cette fonction ne
/// rende la main (le swarm doit continuer d'être piloté en parallèle pendant
/// ce drainage — voir [`crate::NuxNode::run_tunnel_client_unix`]).
#[cfg(unix)]
pub async fn forward_unix_listener(
    control: Control,
    guard: PeerId,
    service: String,
    listener: UnixListener,
    allowed_uids: Vec<u32>,
    shutdown: CancellationToken,
    grace_period: Duration,
) {
    info!(
        local = ?listener.local_addr().ok(),
        %guard,
        service,
        ?allowed_uids,
        "redirection de socket Unix active"
    );
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((local, _)) => {
                        if !peer_uid_authorized(&local, &allowed_uids) {
                            debug!(service, "connexion Unix refusée: UID non autorisé");
                            drop(local); // silence radio local : fermeture sèche
                            continue;
                        }
                        debug!(service, "connexion Unix locale interceptée (UID autorisé)");
                        let control = control.clone();
                        let service = service.clone();
                        relays.spawn(async move {
                            relay_local(control, guard, &service, local).await;
                        });
                    }
                    Err(e) => {
                        // Erreur transitoire (descripteurs épuisés…) : on
                        // souffle un instant plutôt que de tourner à vide.
                        warn!(error = %e, "échec d'acceptation d'une connexion Unix");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    info!(
        service,
        "arrêt demandé: plus de nouvelle connexion Unix acceptée, drainage des relais en cours"
    );
    let _ = tokio::time::timeout(grace_period, async {
        while relays.join_next().await.is_some() {}
    })
    .await;
}

/// Boucle d'acceptation côté Client : chaque connexion TCP reçue sur
/// `listener` est relayée vers `service` dans une tâche dédiée.
///
/// Retourne dès que `shutdown` est déclenché : plus aucune nouvelle connexion
/// locale n'est acceptée, mais les relais déjà en cours ont jusqu'à
/// `grace_period` pour se terminer d'eux-mêmes. Le swarm du nœud doit
/// continuer d'être piloté en parallèle pendant ce drainage — soit par
/// l'appelant ([`crate::NuxNode::next_event`]), soit en passant par
/// [`crate::NuxNode::run_tunnel_client`] qui combine les deux.
pub async fn forward_listener(
    control: Control,
    guard: PeerId,
    service: String,
    listener: TcpListener,
    shutdown: CancellationToken,
    grace_period: Duration,
) {
    info!(
        local = ?listener.local_addr().ok(),
        %guard,
        service,
        "redirection de port active"
    );
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, from)) => {
                        debug!(%from, service, "connexion locale interceptée");
                        let control = control.clone();
                        let service = service.clone();
                        relays.spawn(async move {
                            forward_connection(control, guard, &service, tcp).await;
                        });
                    }
                    Err(e) => {
                        // Erreur transitoire (descripteurs épuisés…) : on
                        // souffle un instant plutôt que de tourner à vide.
                        warn!(error = %e, "échec d'acceptation d'une connexion locale");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    info!(
        service,
        "arrêt demandé: plus de nouvelle connexion locale acceptée, drainage des relais en cours"
    );
    let _ = tokio::time::timeout(grace_period, async {
        while relays.join_next().await.is_some() {}
    })
    .await;
}

/// Issue d'un service de flux tunnel — support de la télémétrie
/// ([`crate::metrics::Metrics`]) uniquement : ne change rien au silence
/// radio déjà appliqué, aucune information supplémentaire ne part vers le
/// pair quel que soit le motif de refus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum TunnelOutcome {
    /// Abandonné avant établissement : en-tête illisible ou tardif, service
    /// inconnu, rôle manquant, empreinte inattendue, service local
    /// injoignable, ou pair parti avant l'acquittement.
    Denied,
    /// Établi (acquittement envoyé) puis relayé jusqu'à sa fermeture, avec ou
    /// sans erreur d'E/S en cours de route.
    Served {
        /// Octets reçus du pair et relayés vers le service local.
        bytes_from_peer: u64,
        /// Octets reçus du service local et relayés vers le pair.
        bytes_to_peer: u64,
    },
}

/// Côté Guard : sert un flux tunnel entrant d'un pair dont la session
/// authentifiée a déjà été contrôlée par l'appelant ; `roles` est la copie
/// des rôles de cette session à l'instant de l'ouverture.
pub(crate) async fn serve_stream(
    peer: PeerId,
    stream: libp2p::Stream,
    roles: Vec<String>,
    registry: Arc<TunnelRegistry>,
) -> TunnelOutcome {
    serve_io(peer, stream.compat(), &roles, &registry).await
}

/// Cœur du service d'un flux tunnel, générique pour être testable hors
/// réseau. Toute anomalie retourne sans un octet écrit : l'abandon du flux
/// EST le refus (silence radio).
async fn serve_io<S>(
    peer: PeerId,
    mut stream: S,
    roles: &[String],
    registry: &TunnelRegistry,
) -> TunnelOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header = match tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut stream)).await {
        Ok(Ok(header)) => header,
        Ok(Err(e)) => {
            debug!(%peer, error = %e, "en-tête de tunnel illisible: flux abandonné");
            return TunnelOutcome::Denied;
        }
        Err(_) => {
            debug!(%peer, "en-tête de tunnel jamais reçu: flux abandonné");
            return TunnelOutcome::Denied;
        }
    };
    let Some(service) = registry.get(&header.service) else {
        debug!(%peer, service = %header.service, "service non exposé: flux abandonné");
        return TunnelOutcome::Denied;
    };
    if !role_granted(roles, service.required_role.as_deref()) {
        debug!(
            %peer,
            service = %header.service,
            "rôle requis absent de la session: flux abandonné"
        );
        return TunnelOutcome::Denied;
    }
    if let Some(expected) = registry.expected_binary_sha256(&peer) {
        if !constant_time_eq(&header.binary_sha256, &expected) {
            debug!(
                %peer,
                service = %header.service,
                "empreinte de binaire inattendue: flux abandonné"
            );
            return TunnelOutcome::Denied;
        }
    }
    let mut local = match TcpStream::connect(service.target).await {
        Ok(local) => local,
        Err(e) => {
            warn!(
                %peer,
                service = %header.service,
                target = %service.target,
                error = %e,
                "service local injoignable: flux abandonné"
            );
            return TunnelOutcome::Denied;
        }
    };
    if stream.write_all(&[TUNNEL_ACK]).await.is_err() || stream.flush().await.is_err() {
        debug!(%peer, service = %header.service, "pair parti avant l'acquittement");
        return TunnelOutcome::Denied;
    }
    info!(%peer, service = %header.service, "tunnel établi");
    match tokio::io::copy_bidirectional(&mut stream, &mut local).await {
        Ok((from_peer, to_peer)) => {
            info!(%peer, service = %header.service, from_peer, to_peer, "tunnel refermé");
            TunnelOutcome::Served {
                bytes_from_peer: from_peer,
                bytes_to_peer: to_peer,
            }
        }
        Err(e) => {
            debug!(%peer, service = %header.service, error = %e, "tunnel interrompu");
            // Le nombre d'octets déjà relayés avant l'erreur n'est pas
            // exposé par `copy_bidirectional` en cas d'échec : sous-compte
            // ce cas plutôt que d'inventer une valeur.
            TunnelOutcome::Served {
                bytes_from_peer: 0,
                bytes_to_peer: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    fn peer() -> PeerId {
        identity::generate().public().to_peer_id()
    }

    /// En-tête de test : empreinte de binaire arbitraire, non pertinente tant
    /// qu'aucun test n'enregistre d'attente pour le pair concerné.
    fn header(service: &str) -> TunnelHeader {
        TunnelHeader {
            service: service.into(),
            binary_sha256: [0u8; SHA256_LEN],
        }
    }

    #[test]
    fn registry_has_anti_amplification_caps_by_default() {
        let registry = TunnelRegistry::new();
        assert_eq!(
            registry.max_streams_per_peer(),
            DEFAULT_MAX_STREAMS_PER_PEER
        );
        assert_eq!(registry.max_streams_total(), DEFAULT_MAX_STREAMS_TOTAL);
        let mut registry = TunnelRegistry::new();
        registry.max_concurrent_streams(4, 16);
        assert_eq!(registry.max_streams_per_peer(), 4);
        assert_eq!(registry.max_streams_total(), 16);
    }

    #[test]
    fn role_check_covers_all_cases() {
        let granted = vec!["reader".to_string(), "db-writer".to_string()];
        // Aucun rôle requis : tout pair authentifié passe.
        assert!(role_granted(&granted, None));
        assert!(role_granted(&[], None));
        // Rôle présent, quelle que soit sa position.
        assert!(role_granted(&granted, Some("reader")));
        assert!(role_granted(&granted, Some("db-writer")));
        // Rôle absent, y compris préfixes et casse différente.
        assert!(!role_granted(&granted, Some("admin")));
        assert!(!role_granted(&granted, Some("read")));
        assert!(!role_granted(&granted, Some("Reader")));
        assert!(!role_granted(&[], Some("reader")));
    }

    #[tokio::test]
    async fn header_round_trip_over_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let header = header("postgres");
        write_header(&mut client, &header).await.unwrap();
        let back = read_header(&mut server).await.unwrap();
        assert_eq!(back, header);
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_on_both_sides() {
        // À l'écriture : un nom de service démesuré est refusé avant d'être
        // émis.
        let (mut client, _server) = tokio::io::duplex(64 * 1024);
        let huge = header(&"s".repeat(MAX_TUNNEL_HEADER_SIZE + 1));
        assert!(write_header(&mut client, &huge).await.is_err());

        // À la lecture : une longueur annoncée hors borne est rejetée sans
        // lire la charge.
        let (mut client, mut server) = tokio::io::duplex(4096);
        let oversized = u16::try_from(MAX_TUNNEL_HEADER_SIZE + 1).unwrap();
        client.write_u16(oversized).await.unwrap();
        assert!(read_header(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn unknown_service_gets_radio_silence() {
        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let registry = TunnelRegistry::new();
        let serve = tokio::spawn(async move {
            serve_io(peer(), guard_side, &["admin".to_string()], &registry).await
        });
        write_header(&mut client_side, &header("ghost"))
            .await
            .unwrap();
        // Silence radio : fin de flux sèche, pas un octet de diagnostic.
        let mut buf = [0u8; 1];
        assert_eq!(client_side.read(&mut buf).await.unwrap(), 0);
        assert_eq!(serve.await.unwrap(), TunnelOutcome::Denied);
    }

    #[tokio::test]
    async fn missing_role_gets_radio_silence() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut registry = TunnelRegistry::new();
        registry.expose("db", echo.local_addr().unwrap(), Some("admin".into()));

        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let serve = tokio::spawn(async move {
            serve_io(peer(), guard_side, &["reader".to_string()], &registry).await
        });
        write_header(&mut client_side, &header("db")).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client_side.read(&mut buf).await.unwrap(), 0);
        assert_eq!(serve.await.unwrap(), TunnelOutcome::Denied);
    }

    #[tokio::test]
    async fn authorized_stream_is_acked_and_relayed() {
        // Service local : écho TCP d'une seule connexion.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = socket.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });

        let mut registry = TunnelRegistry::new();
        registry.expose("echo", target, Some("db-writer".into()));

        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let serve = tokio::spawn(async move {
            serve_io(peer(), guard_side, &["db-writer".to_string()], &registry).await
        });

        write_header(&mut client_side, &header("echo"))
            .await
            .unwrap();
        let mut ack = [0u8; 1];
        client_side.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, [TUNNEL_ACK]);

        client_side.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        client_side.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");

        drop(client_side);
        assert!(matches!(serve.await.unwrap(), TunnelOutcome::Served { .. }));
    }

    #[tokio::test]
    async fn unattested_peer_is_not_checked() {
        // Aucune empreinte enregistrée pour ce pair : n'importe quelle
        // empreinte déclarée passe (opt-in par pair).
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        // Accepte puis referme aussitôt : suffisant pour que le flux relayé
        // se termine proprement (sans quoi `copy_bidirectional` bloquerait
        // indéfiniment sur une connexion jamais fermée par personne).
        tokio::spawn(async move {
            if let Ok((stream, _)) = echo.accept().await {
                drop(stream);
            }
        });
        let mut registry = TunnelRegistry::new();
        registry.expose("echo", addr, None);

        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let serve = tokio::spawn(async move { serve_io(peer(), guard_side, &[], &registry).await });
        let mut declared = header("echo");
        declared.binary_sha256 = [0xAB; SHA256_LEN];
        write_header(&mut client_side, &declared).await.unwrap();

        let mut ack = [0u8; 1];
        client_side.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, [TUNNEL_ACK]);
        drop(client_side);
        assert!(matches!(serve.await.unwrap(), TunnelOutcome::Served { .. }));
    }

    #[tokio::test]
    async fn matching_binary_sha256_is_acked() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = echo.accept().await {
                drop(stream);
            }
        });
        let expected = [0x42; SHA256_LEN];
        let mut registry = TunnelRegistry::new();
        registry.expose("echo", addr, None);
        let attested_peer = peer();
        registry.require_binary_sha256(attested_peer, expected);

        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let serve = tokio::spawn(async move {
            let _ = serve_io(attested_peer, guard_side, &[], &registry).await;
        });
        let mut declared = header("echo");
        declared.binary_sha256 = expected;
        write_header(&mut client_side, &declared).await.unwrap();

        let mut ack = [0u8; 1];
        client_side.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, [TUNNEL_ACK]);
        drop(client_side);
        serve.await.unwrap();
    }

    #[tokio::test]
    async fn mismatched_binary_sha256_gets_radio_silence() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut registry = TunnelRegistry::new();
        registry.expose("echo", echo.local_addr().unwrap(), None);
        let attested_peer = peer();
        registry.require_binary_sha256(attested_peer, [0x42; SHA256_LEN]);

        let (guard_side, mut client_side) = tokio::io::duplex(4096);
        let serve = tokio::spawn(async move {
            let _ = serve_io(attested_peer, guard_side, &[], &registry).await;
        });
        let mut declared = header("echo");
        declared.binary_sha256 = [0xFF; SHA256_LEN];
        write_header(&mut client_side, &declared).await.unwrap();

        // Silence radio : fin de flux sèche, pas un octet de diagnostic.
        let mut buf = [0u8; 1];
        assert_eq!(client_side.read(&mut buf).await.unwrap(), 0);
        serve.await.unwrap();
    }

    #[cfg(unix)]
    mod unix_forwarding {
        use super::*;
        use rustix::process::getuid;
        use std::os::unix::fs::PermissionsExt;

        fn socket_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "nux-tunnel-test-{name}-{}-{}.sock",
                std::process::id(),
                name
            ))
        }

        #[tokio::test]
        async fn bind_forward_socket_sets_owner_only_permissions() {
            let path = socket_path("perms");
            let _ = std::fs::remove_file(&path);

            let _listener = bind_forward_socket(&path).expect("bind de la socket Unix");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "la socket doit être 0600, pas {mode:o}");

            std::fs::remove_file(&path).ok();
        }

        #[tokio::test]
        async fn bind_forward_socket_replaces_a_stale_socket_only() {
            let path = socket_path("stale");
            let _ = std::fs::remove_file(&path);

            // Une première socket "obsolète" au même chemin...
            let first = bind_forward_socket(&path).expect("premier bind");
            drop(first);
            // ...est remplacée sans erreur par un second bind.
            let _second = bind_forward_socket(&path).expect("second bind après la première socket");

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn bind_forward_socket_refuses_to_clobber_a_regular_file() {
            let path = socket_path("regular");
            let _ = std::fs::remove_file(&path);
            std::fs::write(&path, b"pas une socket").unwrap();

            // Un fichier régulier au même chemin n'est jamais supprimé
            // automatiquement : le bind échoue (AddrInUse), pas d'écrasement
            // silencieux d'un fichier qui n'est pas à nous.
            assert!(bind_forward_socket(&path).is_err());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"pas une socket",
                "le fichier régulier ne doit pas avoir été touché"
            );

            std::fs::remove_file(&path).ok();
        }

        #[tokio::test]
        async fn own_uid_is_authorized_by_peer_cred() {
            let path = socket_path("authorized");
            let _ = std::fs::remove_file(&path);
            let listener = bind_forward_socket(&path).unwrap();

            let my_uid = getuid().as_raw();
            let client = UnixStream::connect(&path).await.unwrap();
            let (server_side, _) = listener.accept().await.unwrap();

            // SO_PEERCRED côté serveur rapporte le VRAI uid du process qui a
            // appelé connect() — c'est ce que le noyau garantit, pas ce que
            // le pair prétend être.
            assert!(peer_uid_authorized(&server_side, &[my_uid]));
            assert!(!peer_uid_authorized(&server_side, &[my_uid + 1]));
            assert!(
                !peer_uid_authorized(&server_side, &[]),
                "une liste vide ne doit autoriser personne"
            );

            drop(client);
            std::fs::remove_file(&path).ok();
        }

        #[tokio::test]
        async fn unauthorized_uid_gets_radio_silence_on_the_listener() {
            // Bout en bout sur `forward_unix_listener` : un UID absent de la
            // liste blanche voit sa connexion fermée sans qu'aucun octet du
            // protocole tunnel ne soit échangé (pas d'ouverture de flux
            // Yamux, donc pas de tentative d'appel réseau).
            let path = socket_path("e2e-denied");
            let _ = std::fs::remove_file(&path);
            let listener = bind_forward_socket(&path).unwrap();

            let my_uid = getuid().as_raw();
            let control = {
                // Un swarm minimal, jamais composé : `forward_unix_listener`
                // n'ouvre de flux qu'après l'acceptation d'un UID autorisé,
                // donc ce `Control` ne sera jamais sollicité ici.
                let node = crate::NuxNodeBuilder::new()
                    .build()
                    .expect("construction du nœud de test");
                node.tunnel_control()
            };
            let guard_peer = crate::identity::generate().public().to_peer_id();

            // Liste blanche qui exclut explicitement notre propre UID.
            let forward = tokio::spawn(forward_unix_listener(
                control,
                guard_peer,
                "echo".to_string(),
                listener,
                vec![my_uid + 1],
                CancellationToken::new(),
                Duration::from_secs(5),
            ));

            let mut client = UnixStream::connect(&path).await.unwrap();
            // Silence radio : fin de flux sèche, pas un octet de réponse.
            let mut buf = [0u8; 1];
            assert_eq!(client.read(&mut buf).await.unwrap(), 0);

            forward.abort();
            std::fs::remove_file(&path).ok();
        }
    }
}
