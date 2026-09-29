use anyhow::anyhow;
use oauth2::{
  AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl, basic::BasicClient,
};
use serde::Deserialize;

use super::{Profile, flow::Flow};
use crate::common::config::Config;
use crate::common::errors::ApiError;

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";

#[derive(Deserialize)]
struct GithubUser {
  id: u64,
  login: String,
  name: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
  email: String,
  primary: bool,
  verified: bool,
}

/// The HTTP client used towards the provider. It does not follow redirects, so
/// a provider endpoint cannot bounce the server onto an internal address.
pub fn http_client() -> Result<oauth2::reqwest::Client, ApiError> {
  oauth2::reqwest::ClientBuilder::new()
    .redirect(oauth2::reqwest::redirect::Policy::none())
    .build()
    .map_err(|e| ApiError::InternalError(anyhow!("Failed to build HTTP client: {}", e)))
}

/// Builds the URL to send the browser to, and the flow to remember meanwhile.
pub fn authorize(cfg: &Config, callback_url: String) -> Result<(String, Flow), ApiError> {
  let provider = &cfg.oauth.github;
  if !provider.is_configured() {
    return Err(ApiError::NotFound("Provider is not enabled".to_string()));
  }

  let client = client(
    provider.client_id.clone(),
    provider.client_secret.expose(),
    callback_url,
  )?;
  let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
  let (url, csrf) = client
    .authorize_url(CsrfToken::new_random)
    .set_pkce_challenge(challenge)
    .add_scope(Scope::new("read:user".to_string()))
    .add_scope(Scope::new("user:email".to_string()))
    .url();

  let flow = Flow::new(
    "github",
    csrf.secret().clone(),
    verifier.secret().clone(),
    String::new(),
  );

  Ok((url.to_string(), flow))
}

/// Exchanges the code and reads the account from the GitHub API.
pub async fn profile(
  cfg: &Config,
  callback_url: String,
  code: String,
  flow: &Flow,
) -> Result<Profile, ApiError> {
  let provider = &cfg.oauth.github;
  if !provider.is_configured() {
    return Err(ApiError::NotFound("Provider is not enabled".to_string()));
  }

  let http = http_client()?;
  let client = client(
    provider.client_id.clone(),
    provider.client_secret.expose(),
    callback_url,
  )?;

  let token = client
    .exchange_code(AuthorizationCode::new(code))
    .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
    .request_async(&http)
    .await
    .map_err(|e| ApiError::Unauthorized(format!("Code exchange failed: {}", e)))?;
  let access_token = token.access_token().secret();

  let user: GithubUser = get(&http, USER_URL, access_token).await?;
  let emails: Vec<GithubEmail> = get(&http, EMAILS_URL, access_token).await?;

  // Only the primary, verified address is trusted: GitHub lets an account list
  // addresses it has not proven ownership of.
  let email = emails
    .into_iter()
    .find(|email| email.primary && email.verified)
    .map(|email| email.email);

  Ok(Profile {
    subject: user.id.to_string(),
    email_verified: email.is_some(),
    email,
    name: Some(user.name.unwrap_or(user.login)),
  })
}

async fn get<T: serde::de::DeserializeOwned>(
  http: &oauth2::reqwest::Client,
  url: &str,
  access_token: &str,
) -> Result<T, ApiError> {
  let body = http
    .get(url)
    .bearer_auth(access_token)
    .header("Accept", "application/vnd.github+json")
    // GitHub rejects requests without a user agent.
    .header("User-Agent", env!("CARGO_PKG_NAME"))
    .send()
    .await
    .and_then(|response| response.error_for_status())
    .map_err(|e| ApiError::InternalError(anyhow!("GitHub request failed: {}", e)))?
    .bytes()
    .await
    .map_err(|e| ApiError::InternalError(anyhow!("GitHub request failed: {}", e)))?;

  serde_json::from_slice(&body)
    .map_err(|e| ApiError::InternalError(anyhow!("Unexpected GitHub response: {}", e)))
}

fn client(
  client_id: String,
  client_secret: &str,
  callback_url: String,
) -> Result<
  BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
  >,
  ApiError,
> {
  let invalid =
    |e: oauth2::url::ParseError| ApiError::InternalError(anyhow!("Invalid OAuth URL: {}", e));

  Ok(
    BasicClient::new(ClientId::new(client_id))
      .set_client_secret(ClientSecret::new(client_secret.to_string()))
      .set_auth_uri(AuthUrl::new(AUTH_URL.to_string()).map_err(invalid)?)
      .set_token_uri(TokenUrl::new(TOKEN_URL.to_string()).map_err(invalid)?)
      .set_redirect_uri(RedirectUrl::new(callback_url).map_err(invalid)?),
  )
}
