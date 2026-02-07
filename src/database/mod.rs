pub mod migrations;

use anyhow::Result;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::time::Duration;
use tracing::info;

use crate::common::config::Config;
use crate::database::migrations::Migrator;

#[derive(Clone)]
pub struct Db {
  pub conn: DatabaseConnection,
}

impl Db {
  // We create a single connection pool for Sea-ORM that is shared across the entire application.
  // This prevents the need to open a new connection for every API call, which would be wasteful.
  pub async fn new(cfg: &Config) -> Result<Self, sea_orm::DbErr> {
    let mut opt = ConnectOptions::new(cfg.db_dsn.to_owned());

    // Set connection timeout from environment variable
    opt
      .connect_timeout(Duration::from_secs(cfg.db_timeout))
      // Set idle timeout to 10 minutes
      .idle_timeout(Duration::from_secs(600))
      // Set max lifetime to 30 minutes
      .max_lifetime(Duration::from_secs(1800))
      // Set max connections from environment variable
      .max_connections(cfg.db_pool_max_size)
      // Set min connections to 1
      .min_connections(1);

    info!("Database connection options: {:?}", opt);
    info!("Connecting to database...");
    let conn = Database::connect(opt).await?;
    Ok(Self { conn })
  }

  pub async fn run_migrations(&self) -> Result<(), sea_orm::DbErr> {
    // This integrates database migrations into the application binary to ensure the database
    // is properly migrated during startup.
    Migrator::up(&self.conn, None).await?;
    Ok(())
  }
}
