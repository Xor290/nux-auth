//! Erreurs du moteur Nux-Auth.
//!
//! Règle de cadrage (§3.3) : ces erreurs sont destinées aux journaux et à
//! l'opérateur local. Elles ne doivent JAMAIS être sérialisées vers un pair
//! distant — en cas d'échec d'authentification, le nœud coupe la connexion
//! sans émettre de diagnostic (silence réseau).

use libp2p::TransportError;
use std::io;
use thiserror::Error;

/// Erreur unifiée de la crate `nux-core`.
#[derive(Debug, Error)]
pub enum NuxError {
    /// Problème de chargement ou de validation de l'identité cryptographique.
    #[error("identité: {0}")]
    Identity(String),

    /// Le fichier de clé privée est lisible par d'autres utilisateurs que son
    /// propriétaire (les permissions doivent être 0600 au plus).
    #[error(
        "permissions trop laxistes sur le fichier de clé `{path}`: mode {mode:o}, attendu 0600"
    )]
    InsecureKeyPermissions {
        /// Chemin du fichier incriminé.
        path: String,
        /// Mode Unix constaté.
        mode: u32,
    },

    /// Erreur d'entrée/sortie (fichier de clé, socket…).
    #[error("e/s: {0}")]
    Io(#[from] io::Error),

    /// Échec de construction de la pile réseau libp2p.
    #[error("pile réseau: {0}")]
    Network(String),

    /// L'adresse multiaddr fournie est invalide ou le transport la refuse.
    #[error("transport: {0}")]
    Transport(String),

    /// Échec d'un appel de composition (dial…).
    #[error("connexion: {0}")]
    Dial(String),

    /// Le Guard distant a refusé l'accès — soit par un `Denied` explicite,
    /// soit par une coupure sèche de la connexion (silence radio). Les deux
    /// cas sont volontairement indistinguables côté client.
    #[error("accès refusé par le pair distant")]
    AccessDenied,

    /// Message reçu incompatible avec l'état du handshake.
    #[error("violation de protocole: {0}")]
    Protocol(String),

    /// Échec d'ouverture ou de relais d'un tunnel (Phase 3). Comme les
    /// autres variantes, ce diagnostic reste local : côté réseau, un refus
    /// de tunnel est une coupure sèche du flux.
    #[error("tunnel: {0}")]
    Tunnel(String),

    /// Fichier de configuration illisible, mal formé, ou dont une entrée ne
    /// résiste pas à la validation (adresse, `PeerId`, IP...).
    #[error("configuration: {0}")]
    Config(String),
}

impl From<TransportError<io::Error>> for NuxError {
    fn from(err: TransportError<io::Error>) -> Self {
        NuxError::Transport(err.to_string())
    }
}

/// Alias de résultat pour la crate.
pub type Result<T> = std::result::Result<T, NuxError>;
