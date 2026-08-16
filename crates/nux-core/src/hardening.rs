//! Durcissement du processus contre l'inspection locale (anti-ptrace).
//!
//! ## Le problème
//! L'attestation logicielle ([`crate::attestation`]) et la signature Noise
//! prouvent *quel* code et *quelle* identité ouvrent le tunnel — mais un
//! attaquant qui contrôle le **compte OS** faisant tourner le démon peut
//! agir *à l'intérieur* du processus authentifié : `gdb`/`strace`/`ptrace`
//! pour lire la clé en mémoire ou injecter des octets dans un tunnel déjà
//! établi. Il ne « casse » alors aucune primitive cryptographique : il opère
//! **en tant que** Client légitime, avec sa vraie clé.
//!
//! ## Ce que fait ce module
//! Rend le processus **non « dumpable »** (`prctl(PR_SET_DUMPABLE, 0)` sous
//! Linux). Conséquences immédiates :
//! - `ptrace` (donc `gdb`, `strace`, `lldb`…) par un processus du **même
//!   UID non-root** est refusé ;
//! - `/proc/<pid>/mem`, `/proc/<pid>/environ`, `/proc/<pid>/maps` passent
//!   sous propriété `root`, coupant la lecture mémoire par le même UID ;
//! - le noyau n'écrit plus de *core dump* (qui exposerait la clé sur disque).
//!
//! C'est la même mesure que celle appliquée par `ssh-agent` et `gpg-agent`.
//!
//! ## Ce que ça ne fait PAS (à lire absolument)
//! La véritable frontière de confiance reste le **compte OS (UID)**, pas le
//! processus. Ce durcissement **ne protège pas** contre :
//! - **`root`** : peut toujours ptracer, lire la mémoire, remplacer le
//!   binaire. Rien au niveau logiciel ne l'en empêche ;
//! - **le même UID par un autre vecteur** : un attaquant sous le même
//!   utilisateur peut simplement **lire le fichier de clé `0600`** (il en
//!   est propriétaire) et lancer son propre Client — aucun `gdb` requis ;
//! - **un binaire déjà remplacé/altéré** avant le lancement.
//!
//! Autrement dit : cette mesure **relève le coût** d'une attaque locale même
//! UID (défense en profondeur), elle ne crée pas de frontière *à l'intérieur*
//! d'un compte compromis. Pour une isolation réelle : faire tourner Nux
//! sous un **utilisateur dédié non privilégié**, séparé des applications, et
//! (pour un secret opposable à `root`) s'appuyer sur un module matériel
//! (TPM/HSM/TEE) — hors périmètre de cette bibliothèque.

use crate::error::Result;

/// Rend le processus non « dumpable » (anti-ptrace, anti-core-dump).
/// Idempotent, à appeler au démarrage du démon avant tout usage de la clé.
///
/// Défense en profondeur best-effort : voir les limites détaillées dans la
/// documentation du module ([`crate::hardening`]). Sur les plateformes non
/// Linux, l'opération est un no-op réussi (le modèle `PR_SET_DUMPABLE`
/// n'existe pas).
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| {
        crate::error::NuxError::Io(std::io::Error::other(format!(
            "prctl(PR_SET_DUMPABLE) a échoué: {e}"
        )))
    })
}

/// Variante non-Linux : no-op réussi (pas de modèle `PR_SET_DUMPABLE`).
#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn harden_makes_process_non_dumpable() {
        harden_process().expect("le durcissement doit réussir sous Linux");
        // Effet observable : la lecture de sa PROPRE `environ` passe de
        // permise à refusée une fois le processus non-dumpable (le fichier
        // /proc bascule sous propriété root). C'est le même verrou qui coupe
        // ptrace par le même UID.
        let self_environ = std::fs::read("/proc/self/environ");
        assert!(
            self_environ.is_err(),
            "après durcissement, /proc/self/environ ne doit plus être lisible"
        );
    }
}
