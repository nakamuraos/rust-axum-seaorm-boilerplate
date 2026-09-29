use utoipa::{
  Modify, OpenApi,
  openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme},
};
use utoipa_swagger_ui::{BasicAuth, Config as SwaggerConfig, SwaggerUi};
use utoipauto::utoipauto;

use super::config::Config;

// The OAuth module is behind a Cargo feature, which the scan cannot see, so it
// is left out here and merged by `OAuthAddon` when the feature is on.
#[utoipauto(exclude = ["**/oauth/**"])]
#[derive(OpenApi)]
#[openapi(
  modifiers(&SecurityAddon, &OAuthAddon)
)]
pub struct ApiDoc;

/// Adds the OAuth endpoints to the document when the `oauth2` feature is on.
struct OAuthAddon;

impl Modify for OAuthAddon {
  fn modify(&self, _openapi: &mut utoipa::openapi::OpenApi) {
    #[cfg(feature = "oauth2")]
    _openapi.merge(crate::modules::auth::oauth::ApiDoc::openapi());
  }
}

struct SecurityAddon;

impl Modify for SecurityAddon {
  fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
    // We can unwrap safely since there already is components registered.
    let components = openapi.components.as_mut().unwrap();

    // Add security schemes to the OpenAPI components
    components.add_security_scheme(
      "bearerAuth",
      SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
    );

    // Add API key security scheme to the OpenAPI components
    components.add_security_scheme(
      "api_key",
      SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("api_key"))),
    )
  }
}

/// Create the API documentation using OpenAPI and Swagger UI.
pub fn swagger_ui(cfg: &Config) -> SwaggerUi {
  SwaggerUi::new(cfg.swagger_endpoint.clone())
    .url(
      cfg.swagger_endpoint.clone() + "/api-doc/openapi.json",
      ApiDoc::openapi(),
    )
    .config({
      let mut config = SwaggerConfig::default().persist_authorization(true);
      if !cfg.swagger_basic_auth.is_empty() {
        let parts: Vec<&str> = cfg.swagger_basic_auth.split(':').collect();
        if parts.len() == 2 {
          config = config.basic_auth(BasicAuth {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
          });
        } else {
          // We're immediately panicking here because this is a configuration error that should be
          // caught during application startup.
          panic!("Invalid format for swagger_basic_auth. Expected 'username:password'.");
        }
      }
      config
    })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_oauth_paths_follow_the_feature() {
    let doc = ApiDoc::openapi();

    for path in [
      "/api/v1/auth/oauth/{provider}/login",
      "/api/v1/auth/oauth/{provider}/callback",
    ] {
      assert_eq!(
        doc.paths.paths.contains_key(path),
        cfg!(feature = "oauth2"),
        "{path}"
      );
    }
  }

  #[test]
  fn test_password_login_is_always_documented() {
    assert!(
      ApiDoc::openapi()
        .paths
        .paths
        .contains_key("/api/v1/auth/login")
    );
  }
}
