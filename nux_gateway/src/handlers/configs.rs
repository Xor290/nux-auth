use axum::Json;
use axum::extract::{Path, State};
use diesel::prelude::*;
use nux_core::GuardControl;
use nux_core::PeerId;
use nux_core::attestation::SHA256_LEN;

use crate::db::AppState;
use crate::db::get_conn;
use crate::db::schema::config_node_guards::dsl;
use crate::error::AppError;
use crate::models::{ConfigNodeGuard, ConfigNodeGuardInput, ConfigNodeGuardRow};
use crate::roles::roles_for_config;

fn validate_input(input: &ConfigNodeGuardInput) -> Result<(), AppError> {
    if input.rate_limit.window_secs == 0 {
        return Err(AppError::BadRequest(
            "rate_limit.window_secs doit être d'au moins 1".to_string(),
        ));
    }
    for ip in &input.rate_limit.exempt {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| AppError::BadRequest(format!("rate_limit.exempt `{ip}` invalide")))?;
    }
    for entry in &input.allow {
        entry
            .peer
            .parse::<PeerId>()
            .map_err(|_| AppError::BadRequest(format!("allow.peer `{}` invalide", entry.peer)))?;
    }
    for entry in &input.check_sum {
        entry.peer.parse::<PeerId>().map_err(|_| {
            AppError::BadRequest(format!("check_sum.peer `{}` invalide", entry.peer))
        })?;
        let bytes = hex::decode(entry.sha256.trim()).map_err(|_| {
            AppError::BadRequest(format!("check_sum.sha256 `{}` invalide", entry.sha256))
        })?;
        if bytes.len() != SHA256_LEN {
            return Err(AppError::BadRequest(format!(
                "check_sum.sha256 `{}` doit faire {SHA256_LEN} octets",
                entry.sha256
            )));
        }
    }
    Ok(())
}

/// `PUT /api/v1/configs/:uuid` — appelée par le dashboard (jeton admin). Valide,
/// persiste, puis pousse immédiatement les rôles dérivés dans la liste
/// blanche vive du nœud embarqué (voir [`crate::roles`]) : un Guard
/// nouvellement autorisé peut ouvrir un tunnel sans attendre un redémarrage.
pub async fn put_config(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    Json(input): Json<ConfigNodeGuardInput>,
) -> Result<Json<ConfigNodeGuard>, AppError> {
    uuid.parse::<PeerId>()
        .map_err(|_| AppError::BadRequest(format!("uuid `{uuid}` n'est pas un PeerId valide")))?;
    validate_input(&input)?;

    let config = ConfigNodeGuard {
        uuid,
        rate_limit: input.rate_limit,
        allow: input.allow,
        check_sum: input.check_sum,
        updated_at: String::new(),
    };
    let updated_at = unix_now_string();
    let row = config.into_row(updated_at);

    let pool = state.db.clone();
    let saved_row = tokio::task::spawn_blocking(move || -> Result<ConfigNodeGuardRow, AppError> {
        let mut conn = get_conn(&pool)?;
        diesel::insert_into(dsl::config_node_guards)
            .values(&row)
            .on_conflict(dsl::uuid)
            .do_update()
            .set(&row)
            .execute(&mut conn)
            .map_err(|e| {
                tracing::error!(error = %e, "échec écriture config_node_guards");
                AppError::Internal
            })?;
        Ok(row)
    })
    .await
    .map_err(|_| AppError::Internal)??;

    let saved: ConfigNodeGuard = saved_row.into();

    for (peer, roles) in roles_for_config(&saved) {
        if let Err(e) = state
            .guard_ctl
            .send(GuardControl::Allow { peer, roles })
            .await
        {
            tracing::error!(error = %e, "canal de contrôle du nœud fermé: whitelist vive non mise à jour");
        }
    }

    Ok(Json(saved))
}

/// `GET /api/v1/configs/:uuid` — atteinte uniquement via le tunnel côté
/// Guard (rôle `gw-guard`). Limite connue : ce rôle n'est pas scopé par
/// `uuid` (voir `crate::roles`) — tout Guard authentifié peut lire la config
/// d'un autre `uuid`. Accepté en v1, documenté au README ; journalisé ici et
/// soumis à [`crate::rate_limit`] comme seules mitigations tant que
/// l'identité du pair n'est pas plombée jusqu'à cette couche HTTP.
pub async fn get_config(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<Json<ConfigNodeGuard>, AppError> {
    uuid.parse::<PeerId>()
        .map_err(|_| AppError::BadRequest(format!("uuid `{uuid}` n'est pas un PeerId valide")))?;
    tracing::info!(%uuid, "lecture de config via tunnel gw-guard");

    let pool = state.db.clone();
    let row =
        tokio::task::spawn_blocking(move || -> Result<Option<ConfigNodeGuardRow>, AppError> {
            let mut conn = get_conn(&pool)?;
            dsl::config_node_guards
                .filter(dsl::uuid.eq(&uuid))
                .first::<ConfigNodeGuardRow>(&mut conn)
                .optional()
                .map_err(|e| {
                    tracing::error!(error = %e, "échec lecture config_node_guards");
                    AppError::Internal
                })
        })
        .await
        .map_err(|_| AppError::Internal)??;

    match row {
        Some(row) => Ok(Json(row.into())),
        None => Err(AppError::NotFound),
    }
}

/// Horodatage opaque (secondes Unix) — suffisant pour du bookkeeping
/// d'affichage, aucune logique n'en dépend côté Gateway.
fn unix_now_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
