pub mod models;
pub mod repo;
pub mod repo_extensions;
pub mod repo_team;
pub mod repo_team_ui;

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
}

pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = connect(database_url).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}
