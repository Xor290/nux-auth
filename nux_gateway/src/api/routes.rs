use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post, put};

use super::auth::require_bearer;
use crate::db::AppState;
use crate::handlers::{configs, health, node_state, proxy};
use crate::models::{ActorKind, AuthenticatedActor};
use crate::rate_limit::{self, WindowLimiter};

/// Même plafond que les messages `bincode` bornés côté `nux-core`
/// (`protocol::MAX_MESSAGE_LEN`) — pas de raison qu'un message applicatif
/// JSON soit plus généreux qu'un message du protocole tunnel sous-jacent.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Routeur réseau — appelé directement par le dashboard. `PUT /configs/:uuid`
/// exige le jeton admin ; `/healthz` reste public (sonde de supervision).
pub fn admin_router(state: AppState, admin_token: Arc<str>) -> Router {
    let protected = Router::new()
        .route("/api/v1/configs/:uuid", put(configs::put_config))
        .route_layer(middleware::from_fn_with_state(admin_token, require_bearer));

    let public = Router::new().route("/healthz", get(health::healthz));

    protected
        .merge(public)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Routeur exposé en tunnel sous le rôle `gw-guard` : réservé au Guard lui
/// même (son propre `uuid`). Aucune couche bearer ici — la frontière de
/// confiance est le tunnel lui-même (whitelist Ed25519 + rôle, déjà vérifiés
/// par `nux-core` avant que le moindre octet HTTP n'atteigne ce routeur).
///
/// `node_state_limiter` est partagé avec [`client_router`] : le rôle n'étant
/// pas scopé par `uuid` (limite BOLA connue, voir README), la cadence de
/// `POST /nodes/:peer_id/state` doit être comptée globalement, tous ports
/// confondus, pour rester une garde effective plutôt que deux budgets
/// indépendants qui doublent la fenêtre réelle.
pub fn guard_router(state: AppState, node_state_limiter: Arc<WindowLimiter>) -> Router {
    let get_config_limiter = Arc::new(WindowLimiter::new(
        rate_limit::SENSITIVE_ROUTE_MAX_PER_WINDOW,
        rate_limit::SENSITIVE_ROUTE_WINDOW_SECS,
    ));

    let configs_route = Router::new()
        .route("/api/v1/configs/:uuid", get(configs::get_config))
        .route_layer(middleware::from_fn_with_state(
            get_config_limiter,
            rate_limit::enforce,
        ));

    let node_state_route = Router::new()
        .route(
            "/api/v1/nodes/:peer_id/state",
            post(node_state::post_node_state),
        )
        .route_layer(middleware::from_fn_with_state(
            node_state_limiter,
            rate_limit::enforce,
        ));

    configs_route
        .merge(node_state_route)
        .layer(Extension(AuthenticatedActor {
            id: "gwapi-guard".to_string(),
            kind: ActorKind::Guard,
        }))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Routeur exposé en tunnel sous le rôle `gw-client` : flux d'appairage
/// (device flow) + relais d'état, ouvert à tout pair qu'un Guard autorise.
///
/// Voir [`guard_router`] pour `node_state_limiter` : même budget partagé.
pub fn client_router(state: AppState, node_state_limiter: Arc<WindowLimiter>) -> Router {
    let public_routes = Router::new()
        .route("/api/v1/device/code", post(proxy::device_code))
        .route("/api/v1/device/status", get(proxy::device_status))
        .route("/api/v1/keys/public.pem", get(proxy::public_key));

    let node_state_route = Router::new()
        .route(
            "/api/v1/nodes/:peer_id/state",
            post(node_state::post_node_state),
        )
        .route_layer(middleware::from_fn_with_state(
            node_state_limiter,
            rate_limit::enforce,
        ));

    public_routes
        .merge(node_state_route)
        .layer(Extension(AuthenticatedActor {
            id: "gwapi-client".to_string(),
            kind: ActorKind::Client,
        }))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
