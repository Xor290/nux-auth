//! `NuxNodeBuilder` : construction fluide de la pile réseau libp2p.
//!
//! Pile assemblée (cadrage §5) : runtime **tokio**, transport **TCP**,
//! chiffrement de canal **Noise** (XX, clés statiques liées au `PeerId`),
//! multiplexage **Yamux**, et comportement **request-response** portant le
//! protocole d'authentification `/nux/auth/1.0.0`.

use crate::error::{NuxError, Result};
use crate::identity;
use crate::node::{NuxBehaviour, NuxNode, NodeMode};
use crate::protocol::{AUTH_PROTOCOL, NuxCodec};
use crate::rate_limit;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{Multiaddr, SwarmBuilder, dcutr, noise, rendezvous, tcp, yamux};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Délai par défaut avant fermeture d'une connexion inactive.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Délai par défaut accordé à un échange requête/réponse.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Source d'identité choisie par l'appelant ; résolue au `build()`.
enum IdentitySource {
    Ephemeral,
    Provided(Keypair),
    File(PathBuf),
    Env(String),
}

/// Constructeur fluide d'un [`NuxNode`].
///
/// ```no_run
/// use nux_core::{NuxNodeBuilder, NodeMode};
///
/// # fn main() -> nux_core::Result<()> {
/// let node = NuxNodeBuilder::new()
///     .mode(NodeMode::Guard)
///     .identity_file("/etc/nux/node.key")
///     .listen_on("/ip4/0.0.0.0/tcp/4588".parse().expect("multiaddr valide"))
///     .build()?;
/// println!("PeerId: {}", node.local_peer_id());
/// # Ok(())
/// # }
/// ```
pub struct NuxNodeBuilder {
    mode: NodeMode,
    identity: IdentitySource,
    listen_addrs: Vec<Multiaddr>,
    idle_timeout: Duration,
    request_timeout: Duration,
    rate_limit_max: u32,
    rate_limit_window: Duration,
    rate_limit_exempt: Vec<std::net::IpAddr>,
}

impl Default for NuxNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NuxNodeBuilder {
    /// Nouveau builder en mode [`NodeMode::Client`], identité éphémère.
    pub fn new() -> Self {
        Self {
            mode: NodeMode::Client,
            identity: IdentitySource::Ephemeral,
            listen_addrs: Vec::new(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            rate_limit_max: rate_limit::DEFAULT_MAX_PER_WINDOW,
            rate_limit_window: rate_limit::DEFAULT_WINDOW,
            rate_limit_exempt: Vec::new(),
        }
    }

    /// Définit le rôle du nœud (Client ou Guard).
    pub fn mode(mut self, mode: NodeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Utilise une paire de clés déjà en mémoire.
    pub fn identity(mut self, keypair: Keypair) -> Self {
        self.identity = IdentitySource::Provided(keypair);
        self
    }

    /// Charge l'identité depuis un fichier de clé (permissions 0600 exigées).
    pub fn identity_file(mut self, path: impl AsRef<Path>) -> Self {
        self.identity = IdentitySource::File(path.as_ref().to_path_buf());
        self
    }

    /// Charge l'identité depuis une variable d'environnement (hexadécimal).
    pub fn identity_env(mut self, var: impl Into<String>) -> Self {
        self.identity = IdentitySource::Env(var.into());
        self
    }

    /// Ajoute une adresse d'écoute (cumulable).
    pub fn listen_on(mut self, addr: Multiaddr) -> Self {
        self.listen_addrs.push(addr);
        self
    }

    /// Ajuste le délai d'inactivité avant fermeture de connexion.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Ajuste le délai maximal d'un échange d'authentification.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Plafonne les connexions entrantes acceptées par IP source sur une
    /// fenêtre glissante (cadrage §3.4 ; défaut :
    /// [`rate_limit::DEFAULT_MAX_PER_WINDOW`] par
    /// [`rate_limit::DEFAULT_WINDOW`]). Le refus intervient avant le
    /// handshake Noise, sans un octet applicatif.
    pub fn inbound_rate_limit(mut self, max_per_window: u32, window: Duration) -> Self {
        self.rate_limit_max = max_per_window;
        self.rate_limit_window = window;
        self
    }

    /// Exempte une IP de confiance du rate limiting entrant (cumulable).
    /// Contourne la privation de budget pour les clients légitimes derrière
    /// un NAT partagé.
    pub fn rate_limit_exempt(mut self, ip: std::net::IpAddr) -> Self {
        self.rate_limit_exempt.push(ip);
        self
    }

    /// Résout l'identité, assemble la pile tokio + TCP + QUIC + Noise +
    /// Yamux + request-response et retourne le nœud prêt à être piloté.
    pub fn build(self) -> Result<NuxNode> {
        let keypair = match self.identity {
            IdentitySource::Ephemeral => identity::generate(),
            IdentitySource::Provided(kp) => kp,
            IdentitySource::File(path) => identity::from_file(&path)?,
            IdentitySource::Env(var) => identity::from_env(&var)?,
        };

        let request_timeout = self.request_timeout;
        // Le nœud conserve sa paire de clés pour signer les défis (Client) ;
        // le clone est consommé par le swarm pour Noise et le PeerId.
        let node_keypair = keypair.clone();
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NuxError::Network(e.to_string()))?
            // QUIC intègre son propre chiffrement/authentification (TLS 1.3
            // porté par la même identité Ed25519) et son propre
            // multiplexage : contrairement à TCP, pas de `noise`/`yamux` à
            // fournir séparément. Composé inconditionnellement, comme TCP —
            // inerte tant qu'aucune adresse `/udp/.../quic-v1` n'est écoutée
            // ou composée.
            .with_quic()
            // Composé inconditionnellement, comme le transport TCP : reste
            // inerte tant qu'aucune adresse `/p2p-circuit` n'est composée ou
            // écoutée. Fournit le `relay::client::Behaviour` au closure
            // `with_behaviour` ci-dessous.
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| NuxError::Network(e.to_string()))?
            .with_behaviour(|key, relay_client| NuxBehaviour {
                rate_limit: rate_limit::Behaviour::with_exemptions(
                    self.rate_limit_max,
                    self.rate_limit_window,
                    self.rate_limit_exempt,
                ),
                auth: request_response::Behaviour::<NuxCodec>::new(
                    [(AUTH_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default().with_request_timeout(request_timeout),
                ),
                tunnel: libp2p_stream::Behaviour::new(),
                relay_client,
                dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
                rendezvous: rendezvous::client::Behaviour::new(key.clone()),
                keep_alive: libp2p::ping::Behaviour::new(
                    libp2p::ping::Config::new().with_interval(Duration::from_millis(100)),
                ),
            })
            .map_err(|e| NuxError::Network(e.to_string()))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(self.idle_timeout))
            .build();

        for addr in self.listen_addrs {
            swarm.listen_on(addr)?;
        }

        Ok(NuxNode::new(swarm, self.mode, node_keypair))
    }
}
