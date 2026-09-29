//! Login with an external OAuth2 / OpenID Connect provider.
//!
//! The authorization code flow with PKCE runs in two requests: `login`
//! redirects the browser to the provider, and `callback` exchanges the returned
//! code for the identity of the user, who then gets the same token pair as a
//! password login.

mod account;
pub mod controller;
mod flow;
mod github;
#[cfg(feature = "oidc")]
mod oidc;

use axum::{Router, routing::get};
use utoipa::OpenApi;

use crate::app::AppState;

/// The OAuth endpoints of the OpenAPI document.
///
/// `utoipauto` scans the source files without knowing which Cargo features are
/// on, so `api_doc` excludes this module from the scan and merges this document
/// in only when the feature is enabled.
#[derive(OpenApi)]
#[openapi(paths(controller::login, controller::callback))]
pub struct ApiDoc;

/// Which provider a request is for, named by the `{provider}` path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
  Github,
  #[cfg(feature = "oidc")]
  Google,
  #[cfg(feature = "oidc")]
  Oidc,
}

impl Provider {
  pub fn parse(name: &str) -> Option<Self> {
    match name {
      "github" => Some(Self::Github),
      #[cfg(feature = "oidc")]
      "google" => Some(Self::Google),
      #[cfg(feature = "oidc")]
      "oidc" => Some(Self::Oidc),
      _ => None,
    }
  }

  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Github => "github",
      #[cfg(feature = "oidc")]
      Self::Google => "google",
      #[cfg(feature = "oidc")]
      Self::Oidc => "oidc",
    }
  }
}

/// What a provider tells us about the person who just logged in.
pub struct Profile {
  /// The provider's stable id for the account.
  pub subject: String,
  pub email: Option<String>,
  pub email_verified: bool,
  pub name: Option<String>,
}

pub fn router() -> Router<AppState> {
  Router::new()
    .route("/v1/auth/oauth/{provider}/login", get(controller::login))
    .route(
      "/v1/auth/oauth/{provider}/callback",
      get(controller::callback),
    )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_provider_parse_round_trip() {
    for name in ["github", "google", "oidc"] {
      match Provider::parse(name) {
        Some(provider) => assert_eq!(provider.as_str(), name),
        // Only the providers compiled in are known.
        None => assert!(cfg!(not(feature = "oidc")) && name != "github"),
      }
    }
  }

  #[test]
  fn test_provider_parse_rejects_unknown() {
    assert!(Provider::parse("facebook").is_none());
    assert!(Provider::parse("").is_none());
  }
}
