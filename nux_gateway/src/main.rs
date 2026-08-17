mod api;
mod config;
mod db;
mod error;
mod handlers;
mod models;
mod rate_limit;
mod roles;

use std::sync::Arc;

use diesel::prelude::*;
use dotenvy::dotenv;
use nux_core::{GuardAuthenticator, NodeMode, NuxNodeBuilder, TunnelRegistry, Whitelist};
use tokio::sync::mpsc;

use config::Config;
use db::AppState;
use models::ConfigNodeGuardRow;
use roles::{ROLE_CLIENT, ROLE_GUARD, roles_for_config};

const GUARD_CONTROL_CHANNEL_CAPACITY: usize = 64;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let cfg = Config::from_env().unwrap_or_else(|e| {
        eprintln!("configuration invalide: {e}");
        std::process::exit(1);
    });

    let pool = db::build_pool(&cfg.database_url).unwrap_or_else(|e| {
        eprintln!("base de données: {e}");
        std::process::exit(1);
    });

    let whitelist = rebuild_whitelist(&pool);

    let http = reqwest::Client::builder()
        .timeout(cfg.upstream_timeout)
        .build()
        .expect("client reqwest");

    let (guard_ctl_tx, guard_ctl_rx) = mpsc::channel(GUARD_CONTROL_CHANNEL_CAPACITY);

    let app_state = AppState {
        db: pool,
        http,
        dashboard_base_url: Arc::from(cfg.dashboard_base_url.as_str()),
        dashboard_token: cfg.dashboard_token.as_deref().map(Arc::from),
        guard_ctl: guard_ctl_tx,
    };

    let admin_token: Arc<str> = Arc::from(cfg.admin_token.as_str());
    // Partagé entre les deux routeurs : `POST /nodes/:peer_id/state` est
    // accessible depuis le port `gw-guard` comme depuis le port `gw-client`
    // (limite BOLA connue, voir README), donc un seul budget de cadence pour
    // les deux plutôt que deux plafonds indépendants.
    let node_state_limiter = Arc::new(rate_limit::WindowLimiter::new(
        rate_limit::SENSITIVE_ROUTE_MAX_PER_WINDOW,
        rate_limit::SENSITIVE_ROUTE_WINDOW_SECS,
    ));
    let admin = api::admin_router(app_state.clone(), admin_token);
    let guard_api = api::guard_router(app_state.clone(), Arc::clone(&node_state_limiter));
    let client_api = api::client_router(app_state, node_state_limiter);

    tokio::spawn(serve(admin, cfg.admin_addr, "admin"));
    tokio::spawn(serve(
        guard_api,
        std::net::SocketAddr::from(([127, 0, 0, 1], cfg.guard_port)),
        "gwapi-guard",
    ));
    tokio::spawn(serve(
        client_api,
        std::net::SocketAddr::from(([127, 0, 0, 1], cfg.client_port)),
        "gwapi-client",
    ));

    let mut builder = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on(cfg.listen.clone());
    builder = match &cfg.identity_file {
        Some(path) => builder.identity_file(path),
        None => builder.identity_env(config::IDENTITY_ENV_VAR),
    };
    let mut node = builder.build().unwrap_or_else(|e| {
        eprintln!("nœud Nux: {e}");
        std::process::exit(1);
    });

    tracing::info!(peer_id = %node.local_peer_id(), listen = %cfg.listen, "nux_gateway démarré");

    let mut authenticator = GuardAuthenticator::new(whitelist);
    let mut registry = TunnelRegistry::new();
    registry.expose(
        "gwapi-guard",
        std::net::SocketAddr::from(([127, 0, 0, 1], cfg.guard_port)),
        Some(ROLE_GUARD.to_string()),
    );
    registry.expose(
        "gwapi-client",
        std::net::SocketAddr::from(([127, 0, 0, 1], cfg.client_port)),
        Some(ROLE_CLIENT.to_string()),
    );

    node.run_guard_with_control(&mut authenticator, registry, guard_ctl_rx)
        .await;
}

/// Reconstruit la liste blanche vive à partir de toutes les configs déjà en
/// cache SQLite — sans quoi un redémarrage de la Gateway couperait l'accès
/// des Guards déjà provisionnés avant qu'un nouveau `PUT /configs` ne
/// survienne.
fn rebuild_whitelist(pool: &db::DbPool) -> Whitelist {
    use db::schema::config_node_guards::dsl::config_node_guards;

    let mut whitelist = Whitelist::new();
    let mut conn = pool.get().expect("connexion SQLite initiale");
    let rows = config_node_guards
        .load::<ConfigNodeGuardRow>(&mut conn)
        .unwrap_or_else(|e| {
            eprintln!("lecture initiale des configs: {e}");
            std::process::exit(1);
        });

    for row in rows {
        let cfg = row.into();
        for (peer, peer_roles) in roles_for_config(&cfg) {
            whitelist.allow(peer, peer_roles);
        }
    }
    whitelist
}

async fn serve(app: axum::Router, addr: std::net::SocketAddr, name: &'static str) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind {name} sur {addr}: {e}");
            std::process::exit(1);
        });
    tracing::info!(%addr, service = name, "API REST à l'écoute");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("serveur {name}: {e}");
        std::process::exit(1);
    }
}
