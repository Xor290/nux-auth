use std::time::Duration;

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::db::AppState;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `GET /healthz` — publique, jamais bloquée par une panne dashboard : la
/// Gateway elle-même est saine dès qu'elle répond ; l'accessibilité du
/// dashboard n'est qu'une information annexe (`dashboard:
/// "ok"|"unreachable"`), pas une condition de statut HTTP.
pub async fn healthz(State(state): State<AppState>) -> Json<Value> {
    let url = format!("{}/api/v1/public/healthz", state.dashboard_base_url);
    let dashboard = match state.http.get(url).timeout(PROBE_TIMEOUT).send().await {
        Ok(resp) if resp.status().is_success() => "ok",
        _ => "unreachable",
    };
    Json(json!({ "status": "ok", "dashboard": dashboard }))
}
