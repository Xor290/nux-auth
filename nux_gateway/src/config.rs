use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Nom de la variable d'environnement portant l'identité en hexadécimal —
/// même nom que `nux-cli` (`IDENTITY_ENV_VAR`), pour rester un remplacement
/// direct dans l'outillage d'un opérateur qui connaît déjà `nux guard`.
pub const IDENTITY_ENV_VAR: &str = "NUX_IDENTITY_KEY";

/// Configuration résolue de la Gateway, entièrement dérivée de l'environnement
/// (`.env` ou variables réelles). Fail-closed : un jeton d'authentification
/// admin absent ou trop court fait échouer le démarrage plutôt que d'exposer
/// une route non protégée.
pub struct Config {
    /// Bind réseau pour l'API REST appelée directement par le dashboard.
    pub admin_addr: SocketAddr,
    /// Adresse d'écoute libp2p (Guard/Client s'y connectent par tunnel,
    /// exactement comme ils se connecteraient à un `nux guard` classique).
    pub listen: nux_core::Multiaddr,
    /// Fichier d'identité Ed25519 (`--identity` d'un Guard classique). Si
    /// absent, repli sur `NUX_IDENTITY_KEY` (variable d'environnement).
    pub identity_file: Option<PathBuf>,
    /// Port loopback exposé en tunnel sous le rôle `gw-guard` (voir
    /// `ROLE_GUARD`) : lecture de config, relais d'état — réservé aux pairs
    /// qui SONT un Guard enregistré (leur propre `uuid`).
    pub guard_port: u16,
    /// Port loopback exposé en tunnel sous le rôle `gw-client` (voir
    /// `ROLE_CLIENT`) : flux d'appairage (device flow) + relais d'état —
    /// ouvert à tout pair autorisé par un Guard (`[[allow]]`).
    pub client_port: u16,
    pub database_url: String,
    pub dashboard_base_url: String,
    /// Jeton présenté par le control plane dashboard (ou l'opérateur) pour
    /// écrire une config de Guard dans le cache local (`PUT
    /// /api/v1/configs/:uuid`).
    pub admin_token: String,
    /// Jeton bearer utilisé par la Gateway pour appeler la route privée
    /// dashboard `POST /api/v1/private/nodes/:peerID/state`. Absent par
    /// défaut : la route de relais d'état répond alors 503 plutôt que
    /// d'échouer silencieusement. Non renouvelé automatiquement (pas de
    /// refresh dashboard implémenté ici) — à faire tourner par l'opérateur.
    pub dashboard_token: Option<String>,
    pub upstream_timeout: Duration,
}

const MIN_TOKEN_LEN: usize = 16;

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let admin_addr = env_or("NUX_GW_ADMIN_ADDR", "0.0.0.0:8088")
            .parse::<SocketAddr>()
            .map_err(|e| format!("NUX_GW_ADMIN_ADDR invalide: {e}"))?;

        let listen = env_or("NUX_GW_LISTEN", "/ip4/0.0.0.0/tcp/4589")
            .parse::<nux_core::Multiaddr>()
            .map_err(|e| format!("NUX_GW_LISTEN invalide: {e}"))?;

        let identity_file = std::env::var("NUX_GW_IDENTITY_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);

        let guard_port = env_or("NUX_GW_GUARD_PORT", "8089")
            .parse::<u16>()
            .map_err(|e| format!("NUX_GW_GUARD_PORT invalide: {e}"))?;
        let client_port = env_or("NUX_GW_CLIENT_PORT", "8090")
            .parse::<u16>()
            .map_err(|e| format!("NUX_GW_CLIENT_PORT invalide: {e}"))?;
        if guard_port == client_port {
            return Err("NUX_GW_GUARD_PORT et NUX_GW_CLIENT_PORT doivent différer".to_string());
        }

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL doit être défini".to_string())?;

        let dashboard_base_url = std::env::var("NUX_GW_API_URL")
            .map_err(|_| "NUX_GW_API_URL doit être défini".to_string())?
            .trim_end_matches('/')
            .to_string();

        let admin_token = required_token("NUX_GW_ADMIN_TOKEN")?;

        let dashboard_token = match std::env::var("NUX_GW_DASHBOARD_TOKEN") {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => None,
        };

        Ok(Self {
            admin_addr,
            listen,
            identity_file,
            guard_port,
            client_port,
            database_url,
            dashboard_base_url,
            admin_token,
            dashboard_token,
            upstream_timeout: Duration::from_secs(10),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn required_token(key: &str) -> Result<String, String> {
    let value = std::env::var(key).map_err(|_| format!("{key} doit être défini"))?;
    if value.len() < MIN_TOKEN_LEN {
        return Err(format!(
            "{key} doit faire au moins {MIN_TOKEN_LEN} caractères"
        ));
    }
    Ok(value)
}
