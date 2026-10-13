pub mod args;
pub mod file;
pub mod oauth;
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
use oauth::{OAuthConfig, OAuthProvider};

pub type Config = Arc<Configuration>;

#[derive(Deserialize)]
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

  /// Login with external OAuth2 / OpenID Connect providers.
  pub oauth: OAuthConfig,
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

    if matches!(env, Environment::Production) {
      assert!(
        jwt_secret.expose().len() >= 32
          && !matches!(
            jwt_secret.expose(),
            "a-string-secret-at-least-256-bits-long"
              | "change-me-to-a-secure-random-string-at-least-256-bits"
          ),
        "Production requires a private JWT secret of at least 32 bytes"
      );
    }

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

    let oauth = OAuthConfig {
      redirect_base_url: resolve(
        &file,
        "oauth.redirect_base_url",
        &[],
        None,
        "http://localhost:8080".to_string(),
      ),
      success_redirect_url: resolve(
        &file,
        "oauth.success_redirect_url",
        &[],
        None,
        String::new(),
      ),
      google: oauth_provider(&file, "google"),
      github: oauth_provider(&file, "github"),
      oidc: oauth_provider(&file, "oidc"),
    };

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
      oauth,
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

impl fmt::Debug for Configuration {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Configuration")
      .field("env", &self.env)
      .field("listen_address", &self.listen_address)
      .field("swagger_endpoint", &self.swagger_endpoint)
      .field("graphql_endpoint", &self.graphql_endpoint)
      .field("db_pool_max_size", &self.db_pool_max_size)
      .field("db_run_migrations", &self.db_run_migrations)
      .field("db_run_seeds", &self.db_run_seeds)
      .finish_non_exhaustive()
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

/// Reads the `oauth.<name>.*` keys of one provider.
fn oauth_provider(file: &FileConfig, name: &str) -> OAuthProvider {
  let key = |field: &str| format!("oauth.{name}.{field}");
  OAuthProvider {
    client_id: resolve(file, &key("client_id"), &[], None, String::new()),
    client_secret: Secret(resolve(
      file,
      &key("client_secret"),
      &[],
      None,
      String::new(),
    )),
    issuer: resolve(file, &key("issuer"), &[], None, String::new()),
  }
}

/// A configuration value that must never be written to the logs.
#[derive(Deserialize, Clone, Default)]
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

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  pub(crate) fn config() -> Config {
    Arc::new(Configuration {
      env: Environment::Production,
      listen_address: "127.0.0.1:8080".parse().unwrap(),
      app_port: 8080,
      swagger_endpoint: "/docs".into(),
      swagger_basic_auth: "docs:private-docs-password".into(),
      graphql_endpoint: "/graphql".into(),
      graphql_basic_auth: "graphql:private-graphql-password".into(),
      db_dsn: "postgres://user:private-db-password@localhost/test".into(),
      db_pool_max_size: 1,
      db_timeout: 5,
      db_run_migrations: false,
      db_run_seeds: false,
      jwt_secret: Secret("unit-test-signing-key-with-at-least-32-bytes".into()),
      jwt_expiration_days: 7,
      jwt_refresh_expiration_days: 30,
      token_retention_days: 7,
      workers_interval_hours: 24,
      bcrypt_cost: 4,
      oauth: OAuthConfig::default(),
    })
  }

  #[test]
  fn security_config_debug_redacts_credentials() {
    let debug = format!("{:?}", config());
    for secret in [
      "private-db-password",
      "private-docs-password",
      "private-graphql-password",
      "unit-test-signing-key",
    ] {
      assert!(
        !debug.contains(secret),
        "Configuration Debug exposes {secret}"
      );
    }
  }

  #[test]
  fn security_production_requires_explicit_jwt_secret() {
    const CHILD: &str = "SECURITY_CONFIG_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
      use crate::common::config::args::Args;
      use clap::Parser;

      const PRIVATE: &str = "private-test-key-with-at-least-32-bytes";
      for secret in [
        None,
        Some("short"),
        Some("a-string-secret-at-least-256-bits-long"),
        Some("change-me-to-a-secure-random-string-at-least-256-bits"),
        Some(PRIVATE),
      ] {
        let mut args = vec![
          "server",
          "--config",
          "/dev/null",
          "--env",
          "production",
          "--database-url",
          "postgres://localhost/test",
        ];
        if let Some(secret) = secret {
          args.extend(["--jwt-secret", secret]);
        }
        let result = std::panic::catch_unwind(|| Configuration::from_args(Args::parse_from(args)));
        if secret == Some(PRIVATE) {
          assert!(
            result.is_ok(),
            "Production rejects an explicit private JWT secret"
          );
        } else {
          let panic = result.expect_err("Production accepts a missing, short or public JWT secret");
          let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("");
          assert!(
            message.contains("Production requires a private JWT secret"),
            "Unexpected configuration failure: {message}"
          );
        }
      }
      return;
    }

    // A subprocess isolates configuration environment variables from parallel tests.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
      .args([
        "--exact",
        "common::config::tests::security_production_requires_explicit_jwt_secret",
        "--nocapture",
      ])
      .env(CHILD, "1")
      .env_remove("JWT_SECRET")
      .output()
      .unwrap();
    assert!(
      output.status.success(),
      "{}",
      String::from_utf8_lossy(&output.stdout)
    );
  }
}
