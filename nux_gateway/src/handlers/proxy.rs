use axum::body::{Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;

use crate::db::AppState;
use crate::error::AppError;

/// Relais borné vers le dashboard : jamais de chemin arbitraire (anti-SSRF /
/// anti-proxy-ouvert — chaque appelant fournit un chemin **fixe, codé en
/// dur**, jamais dérivé d'une entrée client), aucun header du client
/// d'origine transmis (ni `Authorization`, ni cookies), délai borné par le
/// client `reqwest` construit avec `Config::upstream_timeout`. Le statut et
/// le corps de la réponse dashboard sont restitués tels quels : une erreur de
/// validation dashboard (400, 409…) doit atteindre l'appelant inchangée, seule
/// une requête qui n'obtient **aucune** réponse devient un 503 côté Gateway.
pub async fn forward_to_dashboard(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    query: Option<&str>,
    body: Option<Bytes>,
    bearer: Option<&str>,
) -> Result<Response, AppError> {
    let mut url = format!("{}{}", state.dashboard_base_url, path);
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }

    let mut req = state.http.request(method, url);
    if let Some(b) = body {
        req = req.header(CONTENT_TYPE, "application/json").body(b);
    }
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }

    let resp = req.send().await.map_err(|e| {
        tracing::warn!(error = %e, "dashboard injoignable");
        AppError::DashboardUnreachable
    })?;

    let status = resp.status();
    let content_type = resp.headers().get(CONTENT_TYPE).cloned();
    let bytes = resp.bytes().await.map_err(|e| {
        tracing::warn!(error = %e, "lecture de la réponse dashboard interrompue");
        AppError::DashboardUnreachable
    })?;

    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(CONTENT_TYPE, ct);
    }
    builder
        .body(Body::from(bytes))
        .map_err(|_| AppError::Internal)
}

/// `POST /device/code` — chemin public dashboard fixe, corps relayé tel quel.
pub async fn device_code(State(state): State<AppState>, body: Bytes) -> Result<Response, AppError> {
    forward_to_dashboard(
        &state,
        reqwest::Method::POST,
        "/api/v1/public/device/code",
        None,
        Some(body),
        None,
    )
    .await
}

/// `GET /device/status?code=…` — la query string est relayée telle quelle.
pub async fn device_status(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<Response, AppError> {
    forward_to_dashboard(
        &state,
        reqwest::Method::GET,
        "/api/v1/public/device/status",
        query.as_deref(),
        None,
        None,
    )
    .await
}

/// `GET /keys/public.pem` — clé publique RS256 du dashboard, purement statique.
pub async fn public_key(State(state): State<AppState>) -> Result<Response, AppError> {
    forward_to_dashboard(
        &state,
        reqwest::Method::GET,
        "/api/v1/public/keys/public.pem",
        None,
        None,
        None,
    )
    .await
}
