use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::response::Response;
use nux_core::PeerId;
use serde::{Deserialize, Serialize};

use crate::db::AppState;
use crate::error::AppError;
use crate::handlers::proxy::forward_to_dashboard;
use crate::models::AuthenticatedActor;

const ALLOWED_STATES: &[&str] = &["active", "inactive", "relay", "suspended"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetStateInput {
    state: String,
}

#[derive(Serialize)]
struct DashboardStateBody<'a> {
    state: &'a str,
}

/// `POST /api/v1/nodes/:peer_id/state` — montée à la fois sur le routeur
/// Guard et Client (même trafic métier : relayer un changement d'état vers
/// le dashboard). Répond 503 tant que `NUX_GW_DASHBOARD_TOKEN` n'est pas
/// configuré, plutôt que d'accepter silencieusement une requête qu'elle ne
/// peut pas transmettre.
pub async fn post_node_state(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(peer_id): Path<String>,
    Json(body): Json<SetStateInput>,
) -> Result<Response, AppError> {
    peer_id
        .parse::<PeerId>()
        .map_err(|_| AppError::BadRequest(format!("peer_id `{peer_id}` invalide")))?;
    if !ALLOWED_STATES.contains(&body.state.as_str()) {
        return Err(AppError::BadRequest(format!(
            "state doit être l'un de {ALLOWED_STATES:?}"
        )));
    }
    tracing::info!(
        actor = ?actor.kind,
        actor_router = %actor.id,
        %peer_id,
        state = %body.state,
        "relais d'état vers le dashboard"
    );

    let Some(dashboard_token) = state.dashboard_token.clone() else {
        return Err(AppError::DashboardNotConfigured);
    };

    let payload = serde_json::to_vec(&DashboardStateBody { state: &body.state })
        .expect("DashboardStateBody sérialisable");

    forward_to_dashboard(
        &state,
        reqwest::Method::POST,
        &format!("/api/v1/private/nodes/{peer_id}/state"),
        None,
        Some(payload.into()),
        Some(&dashboard_token),
    )
    .await
}
