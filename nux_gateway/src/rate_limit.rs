//! Limiteur de cadence global pour les deux routes REST sensibles exposées
//! en tunnel (`GET /configs/:uuid`, `POST /nodes/:peer_id/state`).
//!
//! Ce n'est **pas** un contrôle d'identité : tout le trafic tunnel arrive
//! sur `127.0.0.1` via le relais TCP générique de `nux-core`
//! ([`nux_core::tunnel`]), qui ne transmet à l'application HTTP aucune
//! information sur le `PeerId` qui a ouvert le flux. La limite BOLA
//! documentée au README (un Guard authentifié peut lire ou relayer l'état
//! d'un `uuid` qui n'est pas le sien) reste entière. Ce limiteur borne
//! seulement le débit qu'un pair malveillant peut en tirer — énumération de
//! configs, usurpations répétées de relais d'état — en attendant la
//! mitigation v2 (port + rôle dédiés par `uuid`, qui suppose de rendre le
//! `TunnelRegistry` mutable à chaud côté `nux-core`).
//!
//! Fenêtre fixe, comptage global (pas par appelant, faute d'un appelant
//! identifiable) : volontairement le plus simple des schémas de cadence, à
//! l'image de [`nux_core::rate_limit`] mais sans la dimension par IP qui n'a
//! ici aucun sens.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

/// Cadence par défaut des routes sensibles : généreuse pour ne pas gêner un
/// grand nombre de Guards qui synchronisent leur config sur ce même port
/// partagé, mais elle transforme une énumération automatisée illimitée en
/// un débit borné.
pub const SENSITIVE_ROUTE_MAX_PER_WINDOW: u32 = 120;
pub const SENSITIVE_ROUTE_WINDOW_SECS: u64 = 60;

/// Compteur à fenêtre fixe, sans clé (une seule cadence globale).
pub struct WindowLimiter {
    max_per_window: u32,
    window_secs: u64,
    window_start: AtomicU64,
    count: AtomicU32,
}

impl WindowLimiter {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            window_start: AtomicU64::new(unix_now()),
            count: AtomicU32::new(0),
        }
    }

    /// `true` si la requête est admise sous le plafond de la fenêtre
    /// courante. Fenêtre fixe plutôt que glissante : une course entre deux
    /// threads à la bascule de fenêtre laisse au pire passer quelques
    /// requêtes de plus que le plafond, jamais moins — suffisant pour une
    /// garde best-effort, pas une preuve.
    pub fn allow(&self) -> bool {
        let now = unix_now();
        let start = self.window_start.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= self.window_secs {
            self.window_start.store(now, Ordering::Relaxed);
            self.count.store(0, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed) < self.max_per_window
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Middleware `route_layer` : refuse la requête (429) si le limiteur associé
/// à la route est déjà à cadence.
pub async fn enforce(
    State(limiter): State<Arc<WindowLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if limiter.allow() {
        Ok(next.run(req).await)
    } else {
        tracing::warn!(path = %req.uri().path(), "cadence dépassée sur une route sensible: requête refusée");
        Err(AppError::RateLimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_cap_then_denies_within_the_window() {
        let limiter = WindowLimiter::new(3, 60);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
        assert!(!limiter.allow());
    }
}
