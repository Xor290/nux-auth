//! Configuration TOML d'un nœud Guard.
//!
//! Toute la topologie (écoute, liste blanche, services exposés, rate
//! limiting, attestation logicielle) vit dans ce fichier ; l'identité
//! cryptographique en reste délibérément exclue (`--identity`), pour ne
//! jamais coucher de secret dans un fichier de configuration destiné à être
//! versionné ou copié.
//!
//! ```toml
//! listen = "/ip4/0.0.0.0/tcp/4588"
//!
//! [rate_limit]
//! max = 30
//! window_secs = 60
//! exempt = ["203.0.113.7"]
//!
//! [[allow]]
//! peer = "12D3KooWKSWk..."
//! roles = ["db-writer", "metrics"]
//!
//! [[expose]]
//! name = "postgres"
//! port = 5432
//! role = "db-writer"
//!
//! [[checksum_bin]]
//! peer = "12D3KooWKSWk..."
//! sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
//!
//! relay = "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWAbCdEf..."
//! namespace = "prod-db"
//! ```
//!
//! `[[checksum_bin]]` est une attestation logicielle **best-effort** (voir
//! [`nux_core::attestation`]) : à l'ouverture d'un tunnel, le Client
//! déclare l'empreinte SHA-256 de son propre exécutable ; si ce pair figure
//! ici, le Guard exige qu'elle corresponde, sinon le flux est abandonné sans
//! un octet (silence radio). Un pair absent de cette section n'est soumis à
//! aucun contrôle. Comme le pair déclare lui-même son empreinte, ceci détecte
//! une dérive de build ou un déploiement non conforme, **pas** une
//! usurpation active par un attaquant.
//!
//! `relay` est optionnel : à ne renseigner que si ce Guard n'a pas
//! d'adresse publique joignable. Le nœud réserve alors un circuit auprès du
//! relay désigné (voir `nodes_relay/`) pour rester joignable par les
//! Clients derrière NAT. Un échec de réservation (relay injoignable) n'est
//! jamais fatal au démarrage — le Guard continue de servir ses adresses
//! d'écoute directes, l'échec est seulement journalisé.
//!
//! `namespace` est optionnel et exige `relay` (l'enregistrement transite par
//! cette même connexion) : le Guard s'enregistre sous ce nom logique auprès
//! du point de rendez-vous porté par `nux-relay`, pour qu'un Client le
//! retrouve via `--dial discover:<namespace>@<rendezvous_multiaddr>` sans en
//! connaître l'adresse.

use nux_core::attestation::SHA256_LEN;
use nux_core::{Multiaddr, Namespace, NuxError, PeerId, Whitelist, rate_limit};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// Configuration résolue et validée d'un Guard, prête à construire le nœud.
pub struct GuardConfig {
    pub listen: Multiaddr,
    pub rate_limit_max: u32,
    pub rate_limit_window: Duration,
    pub rate_limit_exempt: Vec<IpAddr>,
    pub whitelist: Whitelist,
    pub expose: Vec<(String, u16, Option<String>)>,
    pub checksum_bin: Vec<(PeerId, [u8; SHA256_LEN])>,
    /// Adresse d'un `nux-relay` (circuit relay v2) auprès duquel réserver
    /// un circuit — utile quand ce Guard n'a pas d'adresse publique
    /// joignable. Absent par défaut : la topologie directe reste le cas
    /// courant, ce champ n'ajoute rien tant qu'il n'est pas renseigné.
    pub relay: Option<Multiaddr>,
    /// Nom logique sous lequel ce Guard s'enregistre auprès du point de
    /// rendezvous porté par `relay`, pour qu'un Client le retrouve sans en
    /// connaître l'adresse. Exige `relay` (l'enregistrement transite par
    /// cette même connexion).
    pub namespace: Option<Namespace>,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    rate_limit: RawRateLimit,
    #[serde(default)]
    allow: Vec<RawAllow>,
    #[serde(default)]
    expose: Vec<RawExpose>,
    #[serde(default)]
    checksum_bin: Vec<RawChecksumBin>,
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
}

fn default_listen() -> String {
    "/ip4/0.0.0.0/tcp/4588".to_string()
}

fn default_rate_max() -> u32 {
    rate_limit::DEFAULT_MAX_PER_WINDOW
}

fn default_rate_window_secs() -> u64 {
    rate_limit::DEFAULT_WINDOW.as_secs()
}

#[derive(Deserialize)]
struct RawRateLimit {
    #[serde(default = "default_rate_max")]
    max: u32,
    #[serde(default = "default_rate_window_secs")]
    window_secs: u64,
    #[serde(default)]
    exempt: Vec<String>,
}

impl Default for RawRateLimit {
    fn default() -> Self {
        Self {
            max: default_rate_max(),
            window_secs: default_rate_window_secs(),
            exempt: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct RawAllow {
    peer: String,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct RawExpose {
    name: String,
    port: u16,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct RawChecksumBin {
    peer: String,
    sha256: String,
}

/// Décode une empreinte SHA-256 hexadécimale (64 caractères).
fn parse_sha256_hex(value: &str) -> Result<[u8; SHA256_LEN], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("hexadécimal invalide: {e}"))?;
    <[u8; SHA256_LEN]>::try_from(bytes).map_err(|b| {
        format!(
            "longueur invalide: {} octets, attendu {SHA256_LEN}",
            b.len()
        )
    })
}

/// Charge et valide la configuration d'un Guard depuis un fichier TOML.
pub fn load(path: &Path) -> nux_core::Result<GuardConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| NuxError::Config(format!("lecture de `{}`: {e}", path.display())))?;
    let raw: RawConfig = toml::from_str(&text)
        .map_err(|e| NuxError::Config(format!("TOML invalide dans `{}`: {e}", path.display())))?;

    let listen = raw
        .listen
        .parse::<Multiaddr>()
        .map_err(|e| NuxError::Config(format!("listen `{}` invalide: {e}", raw.listen)))?;

    if raw.rate_limit.window_secs == 0 {
        return Err(NuxError::Config(
            "rate_limit.window_secs doit être d'au moins 1".into(),
        ));
    }

    let mut rate_limit_exempt = Vec::with_capacity(raw.rate_limit.exempt.len());
    for ip in &raw.rate_limit.exempt {
        let parsed = ip
            .parse::<IpAddr>()
            .map_err(|e| NuxError::Config(format!("rate_limit.exempt `{ip}` invalide: {e}")))?;
        rate_limit_exempt.push(parsed);
    }

    let mut whitelist = Whitelist::new();
    for entry in raw.allow {
        let peer = entry
            .peer
            .parse::<PeerId>()
            .map_err(|e| NuxError::Config(format!("allow.peer `{}` invalide: {e}", entry.peer)))?;
        whitelist.allow(peer, entry.roles);
    }

    let mut seen = HashSet::with_capacity(raw.expose.len());
    let mut expose = Vec::with_capacity(raw.expose.len());
    for entry in raw.expose {
        if !seen.insert(entry.name.clone()) {
            return Err(NuxError::Config(format!(
                "expose: service `{}` défini plusieurs fois",
                entry.name
            )));
        }
        expose.push((entry.name, entry.port, entry.role));
    }

    let mut checksum_bin = Vec::with_capacity(raw.checksum_bin.len());
    for entry in raw.checksum_bin {
        let peer = entry.peer.parse::<PeerId>().map_err(|e| {
            NuxError::Config(format!("checksum_bin.peer `{}` invalide: {e}", entry.peer))
        })?;
        let sha256 = parse_sha256_hex(&entry.sha256).map_err(|e| {
            NuxError::Config(format!(
                "checksum_bin.sha256 `{}` invalide: {e}",
                entry.sha256
            ))
        })?;
        checksum_bin.push((peer, sha256));
    }

    let relay = raw
        .relay
        .map(|addr| {
            addr.parse::<Multiaddr>()
                .map_err(|e| NuxError::Config(format!("relay `{addr}` invalide: {e}")))
        })
        .transpose()?;

    let namespace = raw
        .namespace
        .map(|ns| {
            Namespace::new(ns.clone())
                .map_err(|_| NuxError::Config(format!("namespace `{ns}` invalide: trop long")))
        })
        .transpose()?;
    if namespace.is_some() && relay.is_none() {
        return Err(NuxError::Config(
            "namespace exige `relay` : l'enregistrement transite par cette connexion".into(),
        ));
    }

    Ok(GuardConfig {
        listen,
        rate_limit_max: raw.rate_limit.max,
        rate_limit_window: Duration::from_secs(raw.rate_limit.window_secs),
        rate_limit_exempt,
        whitelist,
        expose,
        checksum_bin,
        relay,
        namespace,
    })
}

/// Config poussée par le dashboard via `nux_gateway` (`GET /api/v1/configs/:uuid`),
/// telle qu'exposée en JSON — même forme que `ConfigNodeGuard` côté Gateway.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct RemoteConfig {
    pub rate_limit: RemoteRateLimit,
    #[serde(default)]
    pub allow: Vec<RemoteAllow>,
    #[serde(default)]
    pub check_sum: Vec<RemoteCheckSum>,
    pub updated_at: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct RemoteRateLimit {
    pub max: u32,
    pub window_secs: u64,
    #[serde(default)]
    pub exempt: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct RemoteAllow {
    pub peer: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct RemoteCheckSum {
    pub peer: String,
    pub sha256: String,
}

/// Réécrit **uniquement** `[rate_limit]`, `[[allow]]` et `[[checksum_bin]]`
/// dans le fichier TOML à `path`, à partir d'une config reçue de la Gateway.
/// Tout le reste (`listen`, `[[expose]]`, `relay`, `namespace`, commentaires
/// de l'opérateur) est préservé à l'octet près — c'est pour ça que ceci
/// utilise `toml_edit` (édition de document, formatage conservé) plutôt que
/// [`load`] (désérialisation en struct typée, formatage perdu).
pub fn apply_remote_config(path: &Path, remote: &RemoteConfig) -> nux_core::Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| NuxError::Config(format!("lecture de `{}`: {e}", path.display())))?;
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| NuxError::Config(format!("TOML invalide dans `{}`: {e}", path.display())))?;

    let mut rate_limit = toml_edit::Table::new();
    rate_limit["max"] = toml_edit::value(i64::from(remote.rate_limit.max));
    rate_limit["window_secs"] =
        toml_edit::value(i64::try_from(remote.rate_limit.window_secs).unwrap_or(i64::MAX));
    let mut exempt = toml_edit::Array::new();
    for ip in &remote.rate_limit.exempt {
        exempt.push(ip.clone());
    }
    rate_limit["exempt"] = toml_edit::value(exempt);
    doc["rate_limit"] = toml_edit::Item::Table(rate_limit);

    let mut allow = toml_edit::ArrayOfTables::new();
    for entry in &remote.allow {
        let mut t = toml_edit::Table::new();
        t["peer"] = toml_edit::value(entry.peer.clone());
        let mut roles = toml_edit::Array::new();
        for role in &entry.roles {
            roles.push(role.clone());
        }
        t["roles"] = toml_edit::value(roles);
        allow.push(t);
    }
    doc["allow"] = toml_edit::Item::ArrayOfTables(allow);

    let mut checksum_bin = toml_edit::ArrayOfTables::new();
    for entry in &remote.check_sum {
        let mut t = toml_edit::Table::new();
        t["peer"] = toml_edit::value(entry.peer.clone());
        t["sha256"] = toml_edit::value(entry.sha256.clone());
        checksum_bin.push(t);
    }
    doc["checksum_bin"] = toml_edit::Item::ArrayOfTables(checksum_bin);

    std::fs::write(path, doc.to_string())
        .map_err(|e| NuxError::Config(format!("écriture de `{}`: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nux-guard-config-test-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("guard.toml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn relay_absent_by_default() {
        let path = write_config("absent", "listen = \"/ip4/127.0.0.1/tcp/4588\"\n");
        let config = load(&path).unwrap();
        assert!(config.relay.is_none());
    }

    #[test]
    fn valid_relay_is_parsed() {
        let path = write_config(
            "valid",
            "listen = \"/ip4/127.0.0.1/tcp/4588\"\n\
             relay = \"/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWKSWkFyEvNTLdch2vGZbvcyxNQBUpFrpccW3nrHPtRWQ4\"\n",
        );
        let config = load(&path).unwrap();
        assert_eq!(
            config.relay,
            Some(
                "/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWKSWkFyEvNTLdch2vGZbvcyxNQBUpFrpccW3nrHPtRWQ4"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn malformed_relay_is_rejected_by_name() {
        let path = write_config("malformed", "relay = \"not-a-multiaddr\"\n");
        let err = match load(&path) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("un relay malformé devait être rejeté au chargement"),
        };
        assert!(
            err.contains("relay") && err.contains("not-a-multiaddr"),
            "le message doit nommer le champ et la valeur fautive: {err}"
        );
    }

    #[test]
    fn namespace_without_relay_is_rejected() {
        let path = write_config(
            "ns-no-relay",
            "listen = \"/ip4/127.0.0.1/tcp/4588\"\nnamespace = \"prod-db\"\n",
        );
        let err = match load(&path) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("namespace sans relay devait être rejeté au chargement"),
        };
        assert!(
            err.contains("namespace") && err.contains("relay"),
            "le message doit expliquer la dépendance namespace -> relay: {err}"
        );
    }

    #[test]
    fn namespace_with_relay_is_parsed() {
        let path = write_config(
            "ns-with-relay",
            "listen = \"/ip4/127.0.0.1/tcp/4588\"\n\
             relay = \"/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWKSWkFyEvNTLdch2vGZbvcyxNQBUpFrpccW3nrHPtRWQ4\"\n\
             namespace = \"prod-db\"\n",
        );
        let config = load(&path).unwrap();
        assert_eq!(
            config.namespace,
            Some(Namespace::new("prod-db".into()).unwrap())
        );
    }
}
