//! Gestion de l'identité cryptographique du nœud (clé Ed25519).
//!
//! Conformément au cadrage (§3.1) :
//! - la clé privée est chargée depuis un fichier en permissions `0600` ou
//!   depuis une variable d'environnement — jamais codée en dur ;
//! - tout tampon intermédiaire contenant le secret est enveloppé dans
//!   [`Zeroizing`] afin que les octets soient physiquement effacés de la
//!   mémoire dès la sortie du scope, même en cas d'erreur (early return).

use crate::error::{NuxError, Result};
use libp2p::identity::{self, Keypair};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Taille d'une clé secrète Ed25519 brute.
pub const ED25519_SECRET_LEN: usize = 32;

/// Charge une identité depuis un fichier contenant les 32 octets bruts de la
/// clé secrète Ed25519.
///
/// Le fichier doit appartenir à l'utilisateur courant avec des permissions
/// n'accordant aucun droit au groupe ni aux autres (`0600` au plus), faute de
/// quoi le chargement est refusé.
pub fn from_file(path: &Path) -> Result<Keypair> {
    ensure_owner_only(path)?;
    let raw = Zeroizing::new(fs::read(path)?);
    keypair_from_secret_bytes(&raw)
        .map_err(|e| NuxError::Identity(format!("fichier `{}`: {e}", path.display())))
}

/// Charge une identité depuis une variable d'environnement contenant la clé
/// secrète Ed25519 encodée en hexadécimal (64 caractères).
///
/// ⚠️ **Sécurité** : l'environnement d'un processus est lisible via
/// `/proc/<pid>/environ` par le même UID, et **hérité par tout sous-processus**
/// lancé par le démon. Cette source convient aux essais et à la CI ; en
/// production, préférer [`from_file`] (fichier `0600`), qui n'expose pas le
/// secret à la descendance du processus.
pub fn from_env(var: &str) -> Result<Keypair> {
    let encoded = Zeroizing::new(
        std::env::var(var)
            .map_err(|_| NuxError::Identity(format!("variable `{var}` absente ou illisible")))?,
    );
    from_hex_str(&encoded).map_err(|e| NuxError::Identity(format!("variable `{var}`: {e}")))
}

/// Décode une clé secrète Ed25519 hexadécimale en [`Keypair`].
fn from_hex_str(encoded: &str) -> std::result::Result<Keypair, String> {
    let raw = Zeroizing::new(
        hex::decode(encoded.trim()).map_err(|_| "hexadécimal invalide".to_string())?,
    );
    keypair_from_secret_bytes(&raw)
}

/// Génère une nouvelle identité Ed25519 aléatoire (entropie système).
pub fn generate() -> Keypair {
    Keypair::generate_ed25519()
}

/// Écrit la clé secrète d'une identité dans `path`, en créant le fichier avec
/// les permissions `0600` dès l'ouverture (aucune fenêtre où il serait lisible
/// par un tiers). Refuse d'écraser un fichier existant.
pub fn save_to_file(keypair: &Keypair, path: &Path) -> Result<()> {
    let ed25519 = keypair
        .clone()
        .try_into_ed25519()
        .map_err(|_| NuxError::Identity("seul Ed25519 est supporté".into()))?;
    let secret = Zeroizing::new(ed25519.secret().as_ref().to_vec());

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;

    use std::io::Write;
    file.write_all(&secret)?;
    file.sync_all()?;
    Ok(())
}

/// Reconstruit un [`Keypair`] à partir des octets bruts de la clé secrète.
/// Le tampon d'entrée est copié dans une zone `Zeroizing` remise à zéro par
/// `ed25519_from_bytes` lui-même après dérivation.
fn keypair_from_secret_bytes(raw: &[u8]) -> std::result::Result<Keypair, String> {
    if raw.len() != ED25519_SECRET_LEN {
        return Err(format!(
            "longueur de clé invalide: {} octets, attendu {ED25519_SECRET_LEN}",
            raw.len()
        ));
    }
    let mut buf = Zeroizing::new([0u8; ED25519_SECRET_LEN]);
    buf.copy_from_slice(raw);
    identity::Keypair::ed25519_from_bytes(&mut *buf).map_err(|e| e.to_string())
}

/// Vérifie que le fichier de clé n'est accessible qu'à son propriétaire.
#[cfg(unix)]
fn ensure_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(NuxError::InsecureKeyPermissions {
            path: path.display().to_string(),
            mode: mode & 0o777,
        });
    }
    Ok(())
}

/// Sur les plateformes non-Unix, le modèle de permissions POSIX n'existe pas ;
/// la responsabilité de protéger le fichier revient à l'opérateur.
#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_file() {
        let dir = std::env::temp_dir().join(format!("nux-id-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        let _ = std::fs::remove_file(&path);

        let keypair = generate();
        save_to_file(&keypair, &path).unwrap();
        let reloaded = from_file(&path).unwrap();
        assert_eq!(
            keypair.public().to_peer_id(),
            reloaded.public().to_peer_id()
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nux-id-test-lax-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lax.key");
        let _ = std::fs::remove_file(&path);

        save_to_file(&generate(), &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            from_file(&path),
            Err(NuxError::InsecureKeyPermissions { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn hex_round_trip() {
        let keypair = generate();
        let secret = keypair.clone().try_into_ed25519().unwrap();
        let reloaded = from_hex_str(&hex::encode(secret.secret().as_ref())).unwrap();
        assert_eq!(
            keypair.public().to_peer_id(),
            reloaded.public().to_peer_id()
        );
        assert!(from_hex_str("zz").is_err());
    }
}
