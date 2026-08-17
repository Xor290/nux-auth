use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use constant_time_eq::constant_time_eq;

use crate::error::AppError;

pub async fn require_bearer(
    State(expected): State<Arc<str>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let ok = match presented {
        Some(token) => {
            token.len() == expected.len() && constant_time_eq(token.as_bytes(), expected.as_bytes())
        }
        None => false,
    };

    if ok {
        Ok(next.run(req).await)
    } else {
        Err(AppError::Unauthorized)
    }
}
