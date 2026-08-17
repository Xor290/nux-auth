use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Erreur applicative unique de la Gateway. Les messages d'authentification
/// restent laconiques (silence radio partiel, cf. modèle de menace Nux) ; les
/// erreurs de validation nomment le champ fautif pour rester exploitables par
/// l'appelant, comme le fait déjà l'API dashboard.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    NotFound,
    BadRequest(String),
    DashboardNotConfigured,
    DashboardUnreachable,
    RateLimited,
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::DashboardNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard non configuré (jeton manquant)".to_string(),
            ),
            AppError::DashboardUnreachable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard control plane injoignable".to_string(),
            ),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "cadence dépassée".to_string(),
            ),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "erreur interne".to_string(),
            ),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
