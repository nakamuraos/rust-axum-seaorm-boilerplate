use anyhow::anyhow;
use openidconnect::{
  AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope,
  core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};

use super::{Profile, flow::Flow, github::http_client};
use crate::common::config::{Config, oauth::OAuthProvider};
use crate::common::errors::ApiError;

/// Google is a plain OIDC provider with a well known issuer.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

pub struct Settings {
  pub issuer: String,
  pub provider: OAuthProvider,
  pub name: &'static str,
}

/// Resolves the configuration of an OIDC provider, or `NotFound` when it is off.
pub fn settings(cfg: &Config, google: bool) -> Result<Settings, ApiError> {
  let not_enabled = || ApiError::NotFound("Provider is not enabled".to_string());

  if google {
    let provider = cfg.oauth.google.clone();
    if !provider.is_configured() {
      return Err(not_enabled());
    }
    return Ok(Settings {
      issuer: GOOGLE_ISSUER.to_string(),
      provider,
      name: "google",
    });
  }

  let provider = cfg.oauth.oidc.clone();
  if !provider.is_oidc_configured() {
    return Err(not_enabled());
  }
  Ok(Settings {
    issuer: provider.issuer.clone(),
    provider,
    name: "oidc",
  })
}

pub async fn authorize(
  settings: &Settings,
  http: &openidconnect::reqwest::Client,
  callback_url: String,
) -> Result<(String, Flow), ApiError> {
  let client = client(settings, http, callback_url).await?;
  let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

  let (url, csrf, nonce) = client
    .authorize_url(
      CoreAuthenticationFlow::AuthorizationCode,
      CsrfToken::new_random,
      Nonce::new_random,
    )
    .set_pkce_challenge(challenge)
    .add_scope(Scope::new("email".to_string()))
    .add_scope(Scope::new("profile".to_string()))
    .url();

  let flow = Flow::new(
    settings.name,
    csrf.secret().clone(),
    verifier.secret().clone(),
    nonce.secret().clone(),
  );

  Ok((url.to_string(), flow))
}

/// Exchanges the code and reads the identity from the verified ID token.
pub async fn profile(
  settings: &Settings,
  http: &openidconnect::reqwest::Client,
  callback_url: String,
  code: String,
  flow: &Flow,
) -> Result<Profile, ApiError> {
  let client = client(settings, http, callback_url).await?;

  let token = client
    .exchange_code(AuthorizationCode::new(code))
    .map_err(|e| ApiError::InternalError(anyhow!("Provider has no token endpoint: {}", e)))?
    .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
    .request_async(http)
    .await
    .map_err(|e| ApiError::Unauthorized(format!("Code exchange failed: {}", e)))?;

  let id_token = openidconnect::TokenResponse::id_token(&token)
    .ok_or_else(|| ApiError::Unauthorized("Provider returned no ID token".to_string()))?;

  // Checks the signature against the provider's keys, the issuer, the audience,
  // the expiry and the nonce.
  let claims = id_token
    .claims(&client.id_token_verifier(), &Nonce::new(flow.nonce.clone()))
    .map_err(|e| ApiError::Unauthorized(format!("Invalid ID token: {}", e)))?;

  Ok(Profile {
    subject: claims.subject().as_str().to_string(),
    email: claims.email().map(|email| email.as_str().to_string()),
    email_verified: claims.email_verified().unwrap_or(false),
    name: claims
      .name()
      .and_then(|name| name.get(None))
      .map(|name| name.as_str().to_string()),
  })
}

pub fn http() -> Result<openidconnect::reqwest::Client, ApiError> {
  http_client()
}

async fn client(
  settings: &Settings,
  http: &openidconnect::reqwest::Client,
  callback_url: String,
) -> Result<
  CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
  >,
  ApiError,
> {
  let issuer = IssuerUrl::new(settings.issuer.clone())
    .map_err(|e| ApiError::InternalError(anyhow!("Invalid issuer URL: {}", e)))?;

  let metadata = CoreProviderMetadata::discover_async(issuer, http)
    .await
    .map_err(|e| ApiError::InternalError(anyhow!("OIDC discovery failed: {}", e)))?;

  Ok(
    CoreClient::from_provider_metadata(
      metadata,
      ClientId::new(settings.provider.client_id.clone()),
      Some(ClientSecret::new(
        settings.provider.client_secret.expose().to_string(),
      )),
    )
    .set_redirect_uri(
      RedirectUrl::new(callback_url)
        .map_err(|e| ApiError::InternalError(anyhow!("Invalid redirect URL: {}", e)))?,
    ),
  )
}
