use clap::Parser;
use std::path::PathBuf;

use super::Environment;

/// Command line overrides for the application configuration.
///
/// Every option is optional: values left unset fall through to the environment
/// and then to the YAML configuration file.
#[derive(Parser, Debug, Default)]
#[command(version, about = "Axum + SeaORM server", long_about = None)]
pub struct Args {
  /// Path to the YAML configuration file
  #[arg(short, long, value_name = "FILE")]
  pub config: Option<PathBuf>,

  /// Environment to run in: development or production
  #[arg(long)]
  pub env: Option<Environment>,

  /// Port to listen on
  #[arg(short, long)]
  pub port: Option<u16>,

  /// Swagger endpoint path
  #[arg(long)]
  pub swagger_endpoint: Option<String>,

  /// Swagger basic auth credentials in the "username:password" format
  #[arg(long)]
  pub swagger_basic_auth: Option<String>,

  /// GraphQL endpoint path
  #[arg(long)]
  pub graphql_endpoint: Option<String>,

  /// GraphQL basic auth credentials in the "username:password" format
  #[arg(long)]
  pub graphql_basic_auth: Option<String>,

  /// Database DSN
  #[arg(long)]
  pub database_url: Option<String>,

  /// Maximum number of connections in the database pool
  #[arg(long)]
  pub database_pool_max_size: Option<u32>,

  /// Database connection timeout in seconds
  #[arg(long)]
  pub database_timeout: Option<u64>,

  /// Run database migrations on startup
  #[arg(long)]
  pub database_run_migrations: Option<bool>,

  /// Run database seeds on startup
  #[arg(long)]
  pub database_run_seeds: Option<bool>,

  /// Secret used to sign JWT tokens
  #[arg(long)]
  pub jwt_secret: Option<String>,

  /// JWT token expiration in days
  #[arg(long)]
  pub jwt_expiration_days: Option<i64>,

  /// Refresh token expiration in days
  #[arg(long)]
  pub jwt_refresh_expiration_days: Option<i64>,

  /// Days a revoked refresh token is kept before being deleted
  #[arg(long)]
  pub token_retention_days: Option<i64>,

  /// Default hours between two runs of a job in watch mode
  #[arg(long)]
  pub workers_interval_hours: Option<u64>,

  /// Bcrypt hashing cost (4-31)
  #[arg(long)]
  pub bcrypt_cost: Option<u32>,

  /// Sub-command, used by binaries that take one (the server ignores it).
  #[arg(value_name = "COMMAND")]
  pub command: Option<String>,
}
