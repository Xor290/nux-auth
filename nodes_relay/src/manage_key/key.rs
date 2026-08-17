use libp2p::identity::Keypair;
use std::{fs, io, path::Path};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Charge la clé depuis un fichier si elle existe, sinon en génère une nouvelle
/// et la sauvegarde. Le buffer contenant le secret est zeroïsé dès qu'il
/// n'est plus nécessaire.
pub fn load_or_generate_keypair(path: &Path) -> Result<Keypair, Box<dyn std::error::Error>> {
    if path.exists() {
        println!("Chargement de l'identité existante depuis {path:?}");

        // Zeroizing<Vec<u8>> : le contenu est effacé (memset zéro) au Drop,
        // même en cas de panic plus loin dans la fonction.
        let raw: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(path)?);

        let keypair = Keypair::from_protobuf_encoding(&raw)?;
        // `raw` sort de scope ici -> zeroization automatique du buffer déchiffré.

        Ok(keypair)
    } else {
        println!("Aucune identité trouvée, génération d'une nouvelle clé...");

        let keypair = Keypair::generate_ed25519();

        // to_protobuf_encoding retourne un Vec<u8> "normal" -> on le wrap
        // immédiatement pour garantir le zeroize même si l'écriture échoue.
        let encoded: Zeroizing<Vec<u8>> = Zeroizing::new(keypair.to_protobuf_encoding()?);

        write_secret_file(path, &encoded)?;

        Ok(keypair)
    }
}

/// Écrit le secret sur disque avec des permissions restrictives (0600 sur Unix)
/// pour que seul le propriétaire du process puisse le lire.
fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // rw pour le owner uniquement
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}
