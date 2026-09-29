use axum::{
  Json,
  extract::{Path, Query, State},
  http::{HeaderMap, header},
  response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::{
  Profile, Provider, account,
  flow::{self, Flow},
  github,
};
use crate::app::AppState;
use crate::common::errors::ApiError;
use crate::modules::auth::dto::AuthResponse;

#[derive(Deserialize)]
pub struct CallbackQuery {
  code: Option<String>,
  state: Option<String>,
  /// Set by the provider instead of `code` when the user refuses or it fails.
  error: Option<String>,
}

#[utoipa::path(
  get,
  tag = "Auth",
  path = "/api/v1/auth/oauth/{provider}/login",
  operation_id = "authOAuthLogin",
  params(("provider" = String, Path, description = "`github`, `google` or `oidc`")),
  responses(
    (status = 307, description = "Redirect to the provider, with the login state in a cookie"),
    (status = 404, description = "Unknown or disabled provider"),
    (status = 500, description = "Internal server error")
  )
)]
/// Starts a login: redirects the browser to the provider.
pub async fn login(
  State(state): State<AppState>,
  Path(provider): Path<String>,
) -> Result<Response, ApiError> {
  let provider = parse(&provider)?;
  let callback_url = callback_url(&state, provider);

  let (url, flow) = match provider {
    Provider::Github => github::authorize(&state.cfg, callback_url)?,
    #[cfg(feature = "oidc")]
    Provider::Google | Provider::Oidc => {
      let settings = super::oidc::settings(&state.cfg, provider == Provider::Google)?;
      super::oidc::authorize(&settings, &super::oidc::http()?, callback_url).await?
    }
  };

  let cookie = flow.to_cookie(&state.cfg)?;
  Ok(
    (
      AppendHeaders([(header::SET_COOKIE, cookie)]),
      Redirect::temporary(&url),
    )
      .into_response(),
  )
}

#[utoipa::path(
  get,
  tag = "Auth",
  path = "/api/v1/auth/oauth/{provider}/callback",
  operation_id = "authOAuthCallback",
  params(
    ("provider" = String, Path, description = "`github`, `google` or `oidc`"),
    ("code" = Option<String>, Query, description = "Authorization code from the provider"),
    ("state" = Option<String>, Query, description = "Anti-CSRF value from the provider"),
    ("error" = Option<String>, Query, description = "Set by the provider when the login failed")
  ),
  responses(
    (status = 200, description = "Login successful", body = AuthResponse),
    (status = 303, description = "Redirect to `oauth.success_redirect_url` with the tokens in the fragment"),
    (status = 400, description = "Missing code or state"),
    (status = 401, description = "Invalid state, refused login or unverified email"),
    (status = 404, description = "Unknown or disabled provider"),
    (status = 500, description = "Internal server error")
  )
)]
/// Completes a login: the provider redirects the browser back here.
pub async fn callback(
  State(state): State<AppState>,
  Path(provider): Path<String>,
  Query(query): Query<CallbackQuery>,
  headers: HeaderMap,
) -> Result<Response, ApiError> {
  let provider = parse(&provider)?;

  if let Some(error) = query.error {
    return Err(ApiError::Unauthorized(format!(
      "Provider refused the login: {}",
      error
    )));
  }
  let (Some(code), Some(returned_state)) = (query.code, query.state) else {
    return Err(ApiError::InvalidRequest(
      "Missing code or state".to_string(),
    ));
  };

  let cookie_header = headers
    .get(header::COOKIE)
    .and_then(|value| value.to_str().ok());
  let flow = Flow::from_cookie_header(&state.cfg, cookie_header)?;
  if flow.provider != provider.as_str() || flow.state != returned_state {
    return Err(ApiError::Unauthorized(
      "Invalid or expired OAuth state".to_string(),
    ));
  }

  let callback_url = callback_url(&state, provider);
  let profile: Profile = match provider {
    Provider::Github => github::profile(&state.cfg, callback_url, code, &flow).await?,
    #[cfg(feature = "oidc")]
    Provider::Google | Provider::Oidc => {
      let settings = super::oidc::settings(&state.cfg, provider == Provider::Google)?;
      super::oidc::profile(&settings, &super::oidc::http()?, callback_url, code, &flow).await?
    }
  };

  let auth = account::sign_in(&state.db.conn, &state.cfg, provider.as_str(), profile).await?;
  let clear = AppendHeaders([(header::SET_COOKIE, flow::clear_cookie(&state.cfg))]);

  let target = &state.cfg.oauth.success_redirect_url;
  if target.is_empty() {
    Ok((clear, Json(auth)).into_response())
  } else {
    // In the fragment, so the tokens are never sent to a server or logged.
    let url = format!(
      "{}#token={}&refresh_token={}",
      target, auth.token, auth.refresh_token
    );
    Ok((clear, Redirect::to(&url)).into_response())
  }
}

fn parse(name: &str) -> Result<Provider, ApiError> {
  Provider::parse(name).ok_or_else(|| ApiError::NotFound("Unknown provider".to_string()))
}

fn callback_url(state: &AppState, provider: Provider) -> String {
  format!(
    "{}/api/v1/auth/oauth/{}/callback",
    state.cfg.oauth.redirect_base_url.trim_end_matches('/'),
    provider.as_str()
  )
}
