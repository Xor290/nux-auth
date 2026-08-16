//! Attestation logicielle best-effort (empreinte SHA-256 du binaire).
//!
//! Complète l'authentification cryptographique ([`crate::auth`]) par un
//! indicateur de conformité de build : à l'ouverture de chaque tunnel, le
//! Client joint l'empreinte SHA-256 de son propre exécutable
//! ([`crate::protocol::TunnelHeader::binary_sha256`]) ; le Guard la compare,
//! pour les pairs auxquels il en a enregistré une attendue
//! ([`crate::TunnelRegistry::require_binary_sha256`]), à celle-ci — une
//! discordance abandonne le flux sans un octet (silence radio), à l'image
//! des autres refus du cadrage §3.3.
//!
//! **Portée du contrôle** : le Client calcule et déclare lui-même son
//! empreinte — un pair activement malveillant peut mentir. Ce mécanisme
//! détecte une dérive de build accidentelle ou un déploiement non conforme,
//! **pas** une usurpation active : la preuve d'identité opposable à un
//! attaquant reste l'authentification cryptographique (`PeerId`/signature).

use crate::error::Result;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Taille d'une empreinte SHA-256.
pub const SHA256_LEN: usize = 32;

static BINARY_SHA256: OnceLock<[u8; SHA256_LEN]> = OnceLock::new();

/// Empreinte SHA-256 de l'exécutable en cours d'exécution, mise en cache
/// après le premier calcul — un Client ouvrant de nombreux tunnels
/// (une connexion locale relayée = un tunnel) ne relit ni ne rehache son
/// propre binaire à chaque fois.
pub fn current_binary_sha256() -> Result<[u8; SHA256_LEN]> {
    if let Some(hash) = BINARY_SHA256.get() {
        return Ok(*hash);
    }
    let path = std::env::current_exe()?;
    let bytes = std::fs::read(path)?;
    let digest: [u8; SHA256_LEN] = Sha256::digest(&bytes).into();
    Ok(*BINARY_SHA256.get_or_init(|| digest))
}
