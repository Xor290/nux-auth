use std::sync::Arc;

use nux_core::GuardControl;
use tokio::sync::mpsc;

use super::database::DbPool;

/// État partagé par les trois routeurs axum (admin, guard, client). Bon
/// marché à cloner : pool r2d2 (`Arc` interne), client `reqwest` (`Arc`
/// interne), chaînes enveloppées dans `Arc<str>`, `mpsc::Sender` clonable.
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub http: reqwest::Client,
    pub dashboard_base_url: Arc<str>,
    pub dashboard_token: Option<Arc<str>>,
    /// Canal vers la boucle `run_guard_with_control` : permet à la route
    /// admin (`PUT /configs/:uuid`) de muter la liste blanche à chaud dès
    /// qu'une nouvelle config est poussée par le dashboard, sans redémarrage.
    pub guard_ctl: mpsc::Sender<GuardControl>,
}
