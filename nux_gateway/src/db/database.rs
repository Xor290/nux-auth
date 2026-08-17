use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::error::AppError;

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<SqliteConnection>>;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub fn build_pool(database_url: &str) -> Result<DbPool, String> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder()
        .build(manager)
        .map_err(|e| format!("pool SQLite: {e}"))?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("connexion SQLite initiale: {e}"))?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| format!("migrations: {e}"))?;

    Ok(pool)
}

pub fn get_conn(pool: &DbPool) -> Result<DbConn, AppError> {
    pool.get().map_err(|e| {
        tracing::error!(error = %e, "connexion SQLite indisponible");
        AppError::Internal
    })
}
