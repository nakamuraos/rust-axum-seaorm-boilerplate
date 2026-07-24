pub mod args;
pub mod file;
pub mod shutdown;
pub mod telemetry;

use clap::Parser;
use serde::Deserialize;
use std::{
  fmt,
  net::{Ipv6Addr, SocketAddr},
  str::FromStr,
  sync::Arc,
};
use tracing::info;

use args::Args;
use file::FileConfig;

pub type Config = Arc<Configuration>;

#[derive(Deserialize, Debug)]
pub struct Configuration {
  /// The environment in which to run the application.
  pub env: Environment,

  /// The address to listen on.
  pub listen_address: SocketAddr,

  /// The port to listen on.
  pub app_port: u16,

  /// The swagger endpoint
  pub swagger_endpoint: String,

  /// The swagger basic auth credentials in the format "username:password".
  /// This is used to protect the Swagger endpoint with basic authentication.
  /// If not set, the Swagger endpoint will not be protected.
  pub swagger_basic_auth: String,

  /// The graphql endpoint
  pub graphql_endpoint: String,

  /// The graphql basic auth credentials in the format "username:password".
  /// This is used to protect the GraphQL endpoint with basic authentication.
  /// If not set, the GraphQL endpoint will not be protected.
  pub graphql_basic_auth: String,

  /// The DSN for the database. Currently, only PostgreSQL is supported.
  pub db_dsn: String,

  /// Maximum number of connections in the database pool
  pub db_pool_max_size: u32,

  /// Database connection timeout in seconds
  pub db_timeout: u64,

  /// Whether to run database migrations on startup
  pub db_run_migrations: bool,

  /// Whether to run database seeds on startup
  pub db_run_seeds: bool,

  /// The secret used to sign and verify JWT tokens.
  pub jwt_secret: Secret,

  /// JWT token expiration in days (default: 7)
  pub jwt_expiration_days: i64,

  /// Refresh token expiration in days (default: 30)
  pub jwt_refresh_expiration_days: i64,

  /// Days a revoked refresh token is kept before the cleanup worker deletes it
  pub token_retention_days: i64,

  /// Default hours between two runs of a job in watch mode
  pub workers_interval_hours: u64,

  /// Bcrypt hashing cost (default: 12, range: 4-31)
  pub bcrypt_cost: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub enum Environment {
  Development,
  Production,
}

impl Configuration {
  /// Builds the configuration by parsing the command line arguments.
  ///
  /// Sources are layered by precedence: command line arguments override
  /// environment variables, which override the YAML configuration file, which
  /// overrides the built-in defaults.
  pub fn new() -> Config {
    Self::from_args(Args::parse())
  }

  /// Builds the configuration from already parsed command line arguments.
  pub fn from_args(args: Args) -> Config {
    let file = FileConfig::load(args.config.as_deref());

    let env = resolve(
      &file,
      "env",
      &["APP_ENV"],
      args.env.clone(),
      Environment::Development,
    );

    let app_port = resolve(&file, "serve.port", &["PORT"], args.port, 8080);

    let swagger_endpoint = resolve(
      &file,
      "swagger.endpoint",
      &[],
      args.swagger_endpoint.clone(),
      "/docs".to_string(),
    );

    let swagger_basic_auth = resolve(
      &file,
      "swagger.basic_auth",
      &[],
      args.swagger_basic_auth.clone(),
      String::new(),
    );

    let graphql_endpoint = resolve(
      &file,
      "graphql.endpoint",
      &[],
      args.graphql_endpoint.clone(),
      "/graphql".to_string(),
    );

    let graphql_basic_auth = resolve(
      &file,
      "graphql.basic_auth",
      &[],
      args.graphql_basic_auth.clone(),
      String::new(),
    );

    let db_dsn = resolve_required(&file, "database.url", &[], args.database_url.clone());

    let db_pool_max_size = resolve(
      &file,
      "database.pool_max_size",
      &[],
      args.database_pool_max_size,
      10,
    );

    let db_timeout = resolve(&file, "database.timeout", &[], args.database_timeout, 5);

    // Migrations and seeds run automatically in development only
    let auto_run = matches!(env, Environment::Development);

    let db_run_migrations = resolve(
      &file,
      "database.run_migrations",
      &[],
      args.database_run_migrations,
      auto_run,
    );

    let db_run_seeds = resolve(
      &file,
      "database.run_seeds",
      &[],
      args.database_run_seeds,
      auto_run,
    );

    let jwt_secret = Secret(resolve(
      &file,
      "jwt.secret",
      &[],
      args.jwt_secret.clone(),
      "a-string-secret-at-least-256-bits-long".to_string(),
    ));

    let jwt_expiration_days = resolve(
      &file,
      "jwt.expiration_days",
      &[],
      args.jwt_expiration_days,
      7,
    );

    let jwt_refresh_expiration_days = resolve(
      &file,
      "jwt.refresh_expiration_days",
      &[],
      args.jwt_refresh_expiration_days,
      30,
    );

    let token_retention_days = resolve(
      &file,
      "workers.token_retention_days",
      &[],
      args.token_retention_days,
      7,
    );

    let workers_interval_hours = resolve(
      &file,
      "workers.interval_hours",
      &[],
      args.workers_interval_hours,
      24,
    );

    let bcrypt_cost = resolve(&file, "bcrypt.cost", &[], args.bcrypt_cost, 12);

    file.warn_unknown_keys();

    let listen_address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, app_port));

    let config = Arc::new(Configuration {
      env,
      listen_address,
      app_port,
      swagger_endpoint,
      swagger_basic_auth,
      graphql_endpoint,
      graphql_basic_auth,
      db_dsn,
      db_pool_max_size,
      db_timeout,
      db_run_migrations,
      db_run_seeds,
      jwt_secret,
      jwt_expiration_days,
      jwt_refresh_expiration_days,
      token_retention_days,
      workers_interval_hours,
      bcrypt_cost,
    });

    // Log the current configuration
    info!(?config, "Application configuration loaded");

    config
  }

  /// Sets the database DSN.
  /// This method is used in tests to override the database DSN.
  pub fn set_dsn(&mut self, db_dsn: String) {
    self.db_dsn = db_dsn
  }
}

impl FromStr for Environment {
  type Err = String;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "development" => Ok(Environment::Development),
      "production" => Ok(Environment::Production),
      _ => Err(format!(
        "Invalid environment: {}. Please make sure it is either \"development\" or \"production\".",
        s
      )),
    }
  }
}

pub fn env_var(name: &str) -> String {
  std::env::var(name)
    .map_err(|e| format!("{}: {}", name, e))
    .expect("Missing environment variable")
}

/// A configuration value that must never be written to the logs.
#[derive(Deserialize, Clone)]
pub struct Secret(pub String);

impl Secret {
  pub fn expose(&self) -> &str {
    &self.0
  }
}

impl fmt::Debug for Secret {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("[redacted]")
  }
}

/// Derives the environment variable name of a dotted configuration path, by
/// uppercasing it and replacing the separators with underscores.
fn env_name(path: &str) -> String {
  path.to_uppercase().replace('.', "_")
}

/// Picks the first source that provides a value, in precedence order: command
/// line argument, environment variable, configuration file, default.
///
/// The environment variable is derived from the path; `aliases` names extra
/// variables to accept for it, tried in order after the derived one.
fn resolve<T>(file: &FileConfig, path: &str, aliases: &[&str], arg: Option<T>, default: T) -> T
where
  T: FromStr,
  <T as FromStr>::Err: fmt::Display,
{
  lookup(file, path, aliases, arg).unwrap_or(default)
}

/// Same as [`resolve`], but the value has no default and must be provided.
fn resolve_required<T>(file: &FileConfig, path: &str, aliases: &[&str], arg: Option<T>) -> T
where
  T: FromStr,
  <T as FromStr>::Err: fmt::Display,
{
  lookup(file, path, aliases, arg).unwrap_or_else(|| {
    panic!(
      "Missing configuration value: set {} in the configuration file or the {} environment variable",
      path,
      env_name(path)
    )
  })
}

fn lookup<T>(file: &FileConfig, path: &str, aliases: &[&str], arg: Option<T>) -> Option<T>
where
  T: FromStr,
  <T as FromStr>::Err: fmt::Display,
{
  // Looked up even when a higher precedence source wins, so that the key
  // counts as known and is not reported as a typo.
  let from_file = file.get(path).map(|raw| parse(raw, path));

  if arg.is_some() {
    return arg;
  }

  let from_env = std::iter::once(env_name(path))
    .chain(aliases.iter().map(|alias| alias.to_string()))
    .find_map(|name| env_value(&name, path));

  from_env.or(from_file)
}

/// Reads and parses an environment variable, treating an empty value as unset.
fn env_value<T>(name: &str, path: &str) -> Option<T>
where
  T: FromStr,
  <T as FromStr>::Err: fmt::Display,
{
  let raw = std::env::var(name).ok()?;
  if raw.is_empty() {
    return None;
  }

  Some(parse(&raw, path))
}

fn parse<T>(raw: &str, path: &str) -> T
where
  T: FromStr,
  <T as FromStr>::Err: fmt::Display,
{
  raw
    .parse()
    .unwrap_or_else(|e| panic!("Unable to parse the value of {}: {}", path, e))
}
