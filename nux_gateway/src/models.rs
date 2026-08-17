use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RateLimit {
    pub max: u32,
    pub window_secs: u64,
    #[serde(default)]
    pub exempt: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Allow {
    pub peer: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CheckSum {
    pub peer: String,
    pub sha256: String,
}

/// Payload accepté en écriture (`PUT /api/v1/configs/:uuid`) — même forme que
/// la config métier, sans le `uuid` (porté par le chemin) ni `updated_at`
/// (dérivé côté serveur).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigNodeGuardInput {
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub allow: Vec<Allow>,
    #[serde(default)]
    pub check_sum: Vec<CheckSum>,
}

// Struct utilisée UNIQUEMENT pour Diesel (colonnes SQL brutes)
#[derive(Queryable, Selectable, Insertable, AsChangeset, Debug)]
#[diesel(table_name = crate::db::schema::config_node_guards)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ConfigNodeGuardRow {
    pub uuid: String,
    pub rate_limit_json: String, // stocké en JSON texte
    pub allow_json: String,
    pub check_sum_json: String,
    pub updated_at: String,
}

// Struct "métier", reconstruite après lecture
#[derive(Serialize, Debug, Clone)]
pub struct ConfigNodeGuard {
    pub uuid: String,
    pub rate_limit: RateLimit,
    pub allow: Vec<Allow>,
    pub check_sum: Vec<CheckSum>,
    pub updated_at: String,
}

/// Tranche de confiance sous laquelle une requête a atteint l'API REST : quel
/// routeur tunnel (`gwapi-guard` ou `gwapi-client`, voir `crate::api` et
/// `crate::roles`) l'a servie. Injectée en amont par chaque routeur (elle est
/// donc fixe pour toutes les requêtes qu'il sert), pas déduite du `PeerId`
/// réel de l'appelant — non observable côté HTTP une fois le tunnel
/// réinjecté. Sert au log d'audit, pas à l'autorisation elle-même (déjà
/// tranchée par le rôle de tunnel avant que la requête n'arrive ici).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    Client,
    Guard,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedActor {
    /// Nom du routeur d'origine (ex. `"gwapi-guard"`) — pas un `PeerId`
    /// individuel, voir la limite documentée sur [`ActorKind`].
    pub id: String,
    pub kind: ActorKind,
}

impl ConfigNodeGuard {
    /// Construit la ligne Diesel à insérer/mettre à jour pour ce `uuid`, à
    /// l'instant `updated_at` (RFC 3339) fourni par l'appelant.
    pub fn into_row(self, updated_at: String) -> ConfigNodeGuardRow {
        ConfigNodeGuardRow {
            uuid: self.uuid,
            rate_limit_json: serde_json::to_string(&self.rate_limit)
                .expect("RateLimit sérialisable"),
            allow_json: serde_json::to_string(&self.allow).expect("Vec<Allow> sérialisable"),
            check_sum_json: serde_json::to_string(&self.check_sum)
                .expect("Vec<CheckSum> sérialisable"),
            updated_at,
        }
    }
}

impl From<ConfigNodeGuardRow> for ConfigNodeGuard {
    fn from(row: ConfigNodeGuardRow) -> Self {
        ConfigNodeGuard {
            uuid: row.uuid,
            rate_limit: serde_json::from_str(&row.rate_limit_json)
                .expect("rate_limit_json stocké invalide"),
            allow: serde_json::from_str(&row.allow_json).expect("allow_json stocké invalide"),
            check_sum: serde_json::from_str(&row.check_sum_json)
                .expect("check_sum_json stocké invalide"),
            updated_at: row.updated_at,
        }
    }
}
