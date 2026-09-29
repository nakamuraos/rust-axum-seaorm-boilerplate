use serde::Deserialize;

use super::Secret;

/// Credentials of one external identity provider.
///
/// A provider is enabled when its credentials are set, so leaving them empty
/// keeps the provider (and its routes) switched off.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct OAuthProvider {
  pub client_id: String,
  pub client_secret: Secret,
  /// Issuer URL used for OIDC discovery. Unused by providers with fixed endpoints.
  pub issuer: String,
}

impl OAuthProvider {
  pub fn is_configured(&self) -> bool {
    !self.client_id.is_empty() && !self.client_secret.expose().is_empty()
  }

  /// Whether an OIDC provider has everything discovery needs.
  pub fn is_oidc_configured(&self) -> bool {
    self.is_configured() && !self.issuer.is_empty()
  }
}

/// Settings of the "log in with an external provider" flows.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct OAuthConfig {
  /// Public base URL of this API, used to build the callback URL registered
  /// with each provider: `{redirect_base_url}/api/v1/auth/oauth/{provider}/callback`.
  pub redirect_base_url: String,

  /// Where to send the browser after a successful login, with the tokens in the
  /// URL fragment. When empty, the callback answers with the JSON token pair.
  pub success_redirect_url: String,

  pub google: OAuthProvider,
  pub github: OAuthProvider,
  /// Any OpenID Connect compliant provider (Keycloak, Auth0, Entra ID...).
  pub oidc: OAuthProvider,
}

#[cfg(test)]
mod tests {
  use super::*;

  fn provider(id: &str, secret: &str, issuer: &str) -> OAuthProvider {
    OAuthProvider {
      client_id: id.to_string(),
      client_secret: Secret(secret.to_string()),
      issuer: issuer.to_string(),
    }
  }

  #[test]
  fn test_provider_is_off_by_default() {
    assert!(!OAuthProvider::default().is_configured());
  }

  #[test]
  fn test_provider_needs_id_and_secret() {
    assert!(!provider("id", "", "").is_configured());
    assert!(!provider("", "secret", "").is_configured());
    assert!(provider("id", "secret", "").is_configured());
  }

  #[test]
  fn test_oidc_provider_needs_issuer() {
    assert!(!provider("id", "secret", "").is_oidc_configured());
    assert!(provider("id", "secret", "https://issuer").is_oidc_configured());
  }
}
