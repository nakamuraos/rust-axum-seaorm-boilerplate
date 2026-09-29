//! State carried between the redirect to the provider and its callback.
//!
//! It lives in a short lived, signed, HttpOnly cookie instead of the database,
//! which keeps the flow stateless and ties it to the browser that started it.

use anyhow::anyhow;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::config::Config;
use crate::common::errors::ApiError;

pub const COOKIE_NAME: &str = "oauth_flow";
const COOKIE_PATH: &str = "/api/v1/auth/oauth";
const FLOW_TTL_SECONDS: i64 = 600;

#[derive(Debug, Serialize, Deserialize)]
pub struct Flow {
  pub provider: String,
  /// The anti-CSRF value echoed back by the provider.
  pub state: String,
  /// The PKCE secret proving the code exchange comes from whoever started the flow.
  pub verifier: String,
  /// Binds an OIDC ID token to this login. Unused by plain OAuth2 providers.
  pub nonce: String,
  exp: usize,
}

impl Flow {
  pub fn new(provider: &str, state: String, verifier: String, nonce: String) -> Self {
    Self {
      provider: provider.to_string(),
      state,
      verifier,
      nonce,
      exp: (chrono::Utc::now().timestamp() + FLOW_TTL_SECONDS) as usize,
    }
  }

  pub fn to_cookie(&self, cfg: &Config) -> Result<String, ApiError> {
    let jwt = encode(
      &Header::default(),
      self,
      &EncodingKey::from_secret(&signing_key(cfg)),
    )
    .map_err(|e| ApiError::InternalError(anyhow!("Failed to sign OAuth state: {}", e)))?;

    Ok(cookie(cfg, &jwt, FLOW_TTL_SECONDS))
  }

  /// Reads the flow back from the `Cookie` header, rejecting a missing,
  /// tampered or expired one.
  pub fn from_cookie_header(cfg: &Config, header: Option<&str>) -> Result<Self, ApiError> {
    let invalid = || ApiError::Unauthorized("Invalid or expired OAuth state".to_string());

    let jwt = header
      .and_then(|header| {
        header
          .split(';')
          .filter_map(|pair| pair.trim().split_once('='))
          .find(|(name, _)| *name == COOKIE_NAME)
          .map(|(_, value)| value)
      })
      .ok_or_else(invalid)?;

    decode::<Flow>(
      jwt,
      &DecodingKey::from_secret(&signing_key(cfg)),
      &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| invalid())
  }
}

/// A `Set-Cookie` value that removes the flow cookie.
pub fn clear_cookie(cfg: &Config) -> String {
  cookie(cfg, "", 0)
}

/// Derived from the JWT secret with a domain separator, so a flow cookie can
/// never be replayed as an access token.
fn signing_key(cfg: &Config) -> Vec<u8> {
  let mut hasher = Sha256::new();
  hasher.update(b"oauth-flow:");
  hasher.update(cfg.jwt_secret.expose().as_bytes());
  hasher.finalize().to_vec()
}

fn cookie(cfg: &Config, value: &str, max_age: i64) -> String {
  // Lax, not Strict: the callback is a cross-site top-level navigation from
  // the provider, which Strict would not send the cookie on.
  let secure = if cfg.oauth.redirect_base_url.starts_with("https://") {
    "; Secure"
  } else {
    ""
  };

  format!(
    "{COOKIE_NAME}={value}; Path={COOKIE_PATH}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
  )
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::common::config::{Configuration, args::Args};

  fn config() -> Config {
    Configuration::from_args(Args::parse_from([
      "server",
      "--database-url",
      "postgres://localhost/test",
      "--jwt-secret",
      "test-secret",
    ]))
  }

  fn flow() -> Flow {
    Flow::new("github", "state".into(), "verifier".into(), "nonce".into())
  }

  /// The `Cookie` header a browser would send back for a `Set-Cookie` value.
  fn as_request_header(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
  }

  #[test]
  fn test_flow_cookie_round_trip() {
    let cfg = config();
    let header = as_request_header(&flow().to_cookie(&cfg).unwrap());

    let restored = Flow::from_cookie_header(&cfg, Some(&format!("a=b; {}; c=d", header))).unwrap();

    assert_eq!(restored.provider, "github");
    assert_eq!(restored.state, "state");
    assert_eq!(restored.verifier, "verifier");
    assert_eq!(restored.nonce, "nonce");
  }

  #[test]
  fn test_flow_cookie_rejects_missing_cookie() {
    let cfg = config();

    assert!(Flow::from_cookie_header(&cfg, None).is_err());
    assert!(Flow::from_cookie_header(&cfg, Some("other=1")).is_err());
  }

  #[test]
  fn test_flow_cookie_rejects_tampering() {
    let cfg = config();
    let header = as_request_header(&flow().to_cookie(&cfg).unwrap());

    assert!(Flow::from_cookie_header(&cfg, Some(&format!("{}x", header))).is_err());
  }

  #[test]
  fn test_flow_cookie_rejects_expired_flow() {
    let cfg = config();
    let mut expired = flow();
    expired.exp = (chrono::Utc::now().timestamp() - 3600) as usize;
    let header = as_request_header(&expired.to_cookie(&cfg).unwrap());

    assert!(Flow::from_cookie_header(&cfg, Some(&header)).is_err());
  }

  #[test]
  fn test_flow_cookie_attributes() {
    let cfg = config();
    let set_cookie = flow().to_cookie(&cfg).unwrap();

    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    // The default base URL is plain http, where Secure would drop the cookie.
    assert!(!set_cookie.contains("Secure"));
    assert!(clear_cookie(&cfg).contains("Max-Age=0"));
  }
}
