use utoipa::{
  openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme},
  Modify, OpenApi,
};
use utoipa_swagger_ui::{BasicAuth, Config as SwaggerConfig, SwaggerUi};
use utoipauto::utoipauto;

use super::config::Config;

#[utoipauto]
#[derive(OpenApi)]
#[openapi(
  modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

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
