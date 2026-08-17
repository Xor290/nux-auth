//! Dérivation des rôles de tunnel à partir d'une config de Guard mise en
//! cache. Deux tranches de confiance, portées par [`crate::tunnel_registry`] :
//!
//! - [`ROLE_GUARD`] : réservé au Guard lui-même (son propre `uuid`, qui EST
//!   son `PeerId`) — lecture de sa config, relais de son état.
//! - [`ROLE_CLIENT`] : ouvert à tout pair que ce Guard autorise
//!   (`allow[].peer`) — flux d'appairage (device flow), relais d'état.
//!
//! Limite assumée en v1 : le rôle n'est pas scopé par `uuid` (un seul rôle
//! `gw-guard` partagé par tous les Guards enregistrés). Un Guard authentifié
//! peut donc, techniquement, lire ou modifier l'état d'un `uuid` qui n'est
//! pas le sien — voir le README (section sécurité) pour la mitigation v2
//! envisagée (un service de tunnel + un port par `uuid`).

use nux_core::PeerId;

use crate::models::ConfigNodeGuard;

pub const ROLE_GUARD: &str = "gw-guard";
pub const ROLE_CLIENT: &str = "gw-client";

/// Pour une config donnée : le Guard lui-même (rôles Guard + Client) suivi
/// de chaque pair qu'il autorise (rôle Client seul). Les entrées invalides
/// (`PeerId` non parseable) sont journalisées puis ignorées plutôt que de
/// faire échouer tout le rechargement — une seule ligne corrompue en base ne
/// doit pas priver les autres Guards de leurs rôles.
pub fn roles_for_config(config: &ConfigNodeGuard) -> Vec<(PeerId, Vec<String>)> {
    let mut out = Vec::with_capacity(1 + config.allow.len());

    match config.uuid.parse::<PeerId>() {
        Ok(peer) => out.push((peer, vec![ROLE_GUARD.to_string(), ROLE_CLIENT.to_string()])),
        Err(e) => {
            tracing::warn!(uuid = %config.uuid, error = %e, "uuid de config invalide en PeerId, ignoré")
        }
    }

    for entry in &config.allow {
        match entry.peer.parse::<PeerId>() {
            Ok(peer) => out.push((peer, vec![ROLE_CLIENT.to_string()])),
            Err(e) => {
                tracing::warn!(peer = %entry.peer, error = %e, "allow.peer invalide en PeerId, ignoré")
            }
        }
    }

    out
}
