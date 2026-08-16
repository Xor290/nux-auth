//! # nux-core
//!
//! Moteur d'**Nux-Auth** : tunnels applicatifs chiffrés et authentifiés
//! entre serveurs, bâtis sur la couche pair-à-pair de `rust-libp2p` —
//! sans VPN, sans serveur SSO central.
//!
//! ## Piliers (document de cadrage v1.0.0)
//! - **SSO décentralisé** : l'identité d'un serveur est sa clé publique
//!   (`PeerId`) ; l'accès se prouve par challenge-response signé, validé
//!   localement par le Guard contre sa liste blanche.
//! - **Tunneling furtif** : capture d'un flux TCP local, encapsulation
//!   chiffrée de bout en bout (Noise), réinjection sur `127.0.0.1` distant.
//! - **Masquage de port** : silence radio total face aux pairs non
//!   authentifiés — aucune erreur verbeuse ne quitte jamais le nœud.
//!
//! ## Phase 1
//! Identité Ed25519 à cycle de vie maîtrisé (`zeroize`), pile réseau
//! tokio + TCP + Noise + Yamux via [`NuxNodeBuilder`], protocole
//! d'authentification `request-response` au format `bincode` borné.
//!
//! ## Phase 2
//! Logique complète du challenge-response : liste blanche consultée en temps
//! constant ([`Whitelist`]), défis à usage unique et fenêtre anti-rejeu de
//! 5 s ([`GuardAuthenticator`]), handshake client intégré
//! ([`NuxNode::authenticate`]) et silence radio côté Guard
//! ([`NuxNode::run_guard`]).
//!
//! ## Phase 3
//! Tunneling TCP : redirection d'un port local du Client vers un service
//! exposé par le Guard ([`TunnelRegistry`]), sur des flux Yamux dédiés
//! `/nux/tunnel/1.0.0`. Chaque flux n'est servi qu'aux sessions
//! authentifiées détenant le rôle requis (vérification en temps constant) ;
//! tout autre flux est abandonné sans un octet (silence radio). Voir
//! [`NuxNode::run_guard_with_tunnels`], [`NuxNode::run_tunnel_client`]
//! et [`NuxNode::open_tunnel`].
//!
//! ## Phase 4
//! Durcissement : rate limiting des connexions entrantes par IP, appliqué
//! avant le handshake Noise ([`rate_limit`],
//! [`NuxNodeBuilder::inbound_rate_limit`]) ; boucle client résiliente avec
//! ré-authentification automatique ([`NuxNode::run_client_session`]) ;
//! cibles `cargo-fuzz` sur le codec (répertoire `fuzz/`) et CI GitHub
//! Actions (tests, clippy, rustfmt, `cargo-audit`).
//!
//! ## Phase 5
//! Attestation logicielle best-effort ([`attestation`]) : le Client joint
//! l'empreinte SHA-256 de son propre exécutable à chaque ouverture de tunnel
//! ; le Guard la compare, pour les pairs où il en a enregistré une attendue
//! ([`TunnelRegistry::require_binary_sha256`]), et abandonne le flux sans un
//! octet en cas de discordance. Complète l'authentification cryptographique
//! sans s'y substituer — voir les limites documentées dans [`attestation`].
//! Durcissement du processus ([`hardening`]) : le démon se rend non
//! « dumpable » au démarrage (anti-ptrace/anti-core-dump), pour relever le
//! coût d'une inspection mémoire locale par le même UID — sans remplacer
//! l'isolation par compte OS (limites détaillées dans [`hardening`]).

#![warn(missing_docs)]
pub mod attestation;
pub mod auth;
mod builder;
mod error;
pub mod hardening;
pub mod identity;
pub mod metrics;
mod node;
pub mod protocol;
pub mod rate_limit;
pub mod tunnel;

pub use auth::{AuthOutcome, GuardAuthenticator, Whitelist};
pub use builder::NuxNodeBuilder;
pub use error::{NuxError, Result};
pub use metrics::Metrics;
pub use node::{NuxBehaviour, NuxBehaviourEvent, NuxNode, AuthEvent, GuardControl, NodeMode};
pub use tunnel::{TunnelRegistry, TunnelStream};

// Réexports des types libp2p qui apparaissent dans l'API publique, pour que
// les intégrateurs n'aient pas à épingler eux-mêmes la version de libp2p.
pub use libp2p::{Multiaddr, PeerId, identity::Keypair, rendezvous::Namespace, swarm::SwarmEvent};
