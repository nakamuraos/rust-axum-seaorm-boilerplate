use axum::{
  Extension, Json,
  extract::{Path, Query, State},
  http::{HeaderMap, header},
  response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{
  Profile, Provider, account,
  flow::{self, Flow, Intent},
  github,
};
use crate::app::AppState;
use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::modules::auth::dto::{AuthResponse, OwnershipProofResponse};

use crate::common::extractors::ValidatedJson;
use crate::modules::{
  auth::{dto::LinkIdentityRequest, ownership, service::ensure_active},
  users::{dto::UserDto, entities as users},
};
use sea_orm::EntityTrait;

#[derive(Serialize, ToSchema)]
pub struct AuthorizationResponse {
  pub authorization_url: String,
}

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum CallbackResponse {
  Session(Box<AuthResponse>),
  Proof(OwnershipProofResponse),
}

impl CallbackResponse {
  fn into_callback(self, cfg: &Config) -> Response {
    let headers = AppendHeaders([
      (header::SET_COOKIE, flow::clear_cookie(cfg)),
      (header::CACHE_CONTROL, "no-store".into()),
    ]);
    let target = &cfg.oauth.success_redirect_url;
    if target.is_empty() {
      return (headers, Json(self)).into_response();
    }
    // Fragments keep credentials out of HTTP requests and server logs.
    let url = match self {
      Self::Session(auth) => format!(
        "{}#token={}&refresh_token={}",
        target, auth.token, auth.refresh_token
      ),
      Self::Proof(proof) => format!(
        "{}#account_proof={}&user_id={}",
        target, proof.proof_token, proof.user_id
      ),
    };
    (headers, Redirect::to(&url)).into_response()
  }
}

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
  authorize(&state, &provider, Intent::Login).await
}

async fn authorize(state: &AppState, provider: &str, intent: Intent) -> Result<Response, ApiError> {
  let provider = parse(provider)?;
  let callback_url = callback_url(state, provider);

  let (url, mut flow) = match provider {
    Provider::Github => github::authorize(&state.cfg, callback_url)?,
    #[cfg(feature = "oidc")]
    Provider::Google | Provider::Oidc => {
      let settings = super::oidc::settings(&state.cfg, provider == Provider::Google)?;
      super::oidc::authorize(
        &settings,
        &super::oidc::http()?,
        callback_url,
        !matches!(intent, Intent::Login),
      )
      .await?
    }
  };

  flow.intent = intent;
  let cookie = flow.to_cookie(&state.cfg)?;
  let headers = AppendHeaders([
    (header::SET_COOKIE, cookie),
    (header::CACHE_CONTROL, "no-store".into()),
  ]);
  if matches!(flow.intent, Intent::Login) {
    Ok((headers, Redirect::temporary(&url)).into_response())
  } else {
    Ok(
      (
        headers,
        Json(AuthorizationResponse {
          authorization_url: url,
        }),
      )
        .into_response(),
    )
  }
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
    (status = 200, description = "Session tokens or an account ownership proof", body = CallbackResponse),
    (status = 303, description = "Redirect to `oauth.success_redirect_url` with the tokens in the fragment"),
    (status = 400, description = "Missing code or state"),
    (status = 401, description = "Invalid state, refused login or unverified email"),
    (status = 404, description = "Unknown or disabled provider"),
    (status = 409, description = "Identity belongs to another account; use explicit merge"),
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

  let outcome = match flow.intent {
    Intent::Login => CallbackResponse::Session(
      account::sign_in(&state.db.conn, &state.cfg, provider.as_str(), profile)
        .await?
        .into(),
    ),
    Intent::Link { proof_token } => CallbackResponse::Session(
      account::link_identity(
        &state.db.conn,
        &state.cfg,
        &proof_token,
        provider.as_str(),
        profile,
      )
      .await?
      .into(),
    ),
    Intent::Verify {
      user_id,
      session_version,
    } => CallbackResponse::Proof(
      account::verify_identity(
        &state.db.conn,
        &state.cfg,
        user_id,
        session_version,
        provider.as_str(),
        profile,
      )
      .await?,
    ),
  };
  Ok(outcome.into_callback(&state.cfg))
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

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/oauth/{provider}/link",
  operation_id = "authOAuthLink",
  security(("bearerAuth" = [])),
  params(("provider" = String, Path)),
  request_body = LinkIdentityRequest,
  responses(
    (status = 200, description = "Authorization URL; navigate the browser to it", body = AuthorizationResponse),
    (status = 401, description = "Invalid ownership proof"),
    (status = 409, description = "Identity belongs to another account")
  )
)]
pub async fn link(
  State(state): State<AppState>,
  Path(provider): Path<String>,
  Extension(user): Extension<UserDto>,
  ValidatedJson(req): ValidatedJson<LinkIdentityRequest>,
) -> Result<Response, ApiError> {
  let proof = ownership::verify(&state.cfg, &req.proof_token)?;
  if proof.user_id.to_string() != user.id {
    return Err(ApiError::Unauthorized(
      "Proof belongs to another account".into(),
    ));
  }
  authorize(
    &state,
    &provider,
    Intent::Link {
      proof_token: req.proof_token,
    },
  )
  .await
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/oauth/{provider}/verify",
  operation_id = "authOAuthVerify",
  security(("bearerAuth" = [])),
  params(("provider" = String, Path)),
  responses(
    (status = 200, description = "Authorization URL; callback returns an ownership proof", body = AuthorizationResponse),
    (status = 401, description = "Unauthorized")
  )
)]
pub async fn verify(
  State(state): State<AppState>,
  Path(provider): Path<String>,
  Extension(user): Extension<UserDto>,
) -> Result<Response, ApiError> {
  let id = user
    .id
    .parse::<uuid::Uuid>()
    .map_err(|_| ApiError::Unauthorized("Invalid account ID".into()))?;
  let account = users::Entity::find_by_id(id)
    .one(&state.db.conn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".into()))?;
  ensure_active(&account.status)?;
  authorize(
    &state,
    &provider,
    Intent::Verify {
      user_id: id,
      session_version: account.session_version,
    },
  )
  .await
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::{Secret, tests::config};
  use crate::database::Db;
  use crate::modules::auth::{
    ownership,
    service::{generate_token, tests::user},
  };
  use crate::modules::users::enums::{UserRole, UserStatus};
  use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
  };
  use sea_orm::{DbBackend, MockDatabase};
  use tower::ServiceExt;

  #[tokio::test]
  async fn test_link_returns_browser_url_and_signed_target_intent() {
    let account = user(UserStatus::Active, UserRole::User);
    let mut cfg = config();
    std::sync::Arc::get_mut(&mut cfg)
      .unwrap()
      .oauth
      .github
      .client_id = "client".into();
    std::sync::Arc::get_mut(&mut cfg)
      .unwrap()
      .oauth
      .github
      .client_secret = Secret("secret".into());
    std::sync::Arc::get_mut(&mut cfg)
      .unwrap()
      .oauth
      .redirect_base_url = "http://localhost:8080".into();
    let proof = ownership::issue(&cfg, &account).unwrap().proof_token;
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[account.clone()]])
      .into_connection();
    let state = AppState {
      db: Db { conn: db },
      cfg: cfg.clone(),
    };
    let app = super::super::router(state.clone()).with_state(state);
    let response = app
      .oneshot(
        Request::builder()
          .method("POST")
          .uri("/v1/auth/oauth/github/link")
          .header(
            "authorization",
            format!("Bearer {}", generate_token(&account, &cfg).unwrap()),
          )
          .header("content-type", "application/json")
          .body(Body::from(
            serde_json::json!({"proof_token": proof}).to_string(),
          ))
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    let flow = Flow::from_cookie_header(&cfg, Some(cookie)).unwrap();
    assert!(matches!(flow.intent, Intent::Link { proof_token } if proof_token == proof));
    let body: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    let url = body["authorization_url"].as_str().unwrap();
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
    assert!(url.contains(&format!("state={}", flow.state)));
    assert!(url.contains("code_challenge="));
  }

  #[tokio::test]
  async fn test_connect_endpoints_require_authentication() {
    for path in ["link", "verify"] {
      let state = AppState {
        db: Db {
          conn: MockDatabase::new(DbBackend::Postgres).into_connection(),
        },
        cfg: config(),
      };
      let app = super::super::router(state.clone()).with_state(state);
      let response = app
        .oneshot(
          Request::builder()
            .method("POST")
            .uri(format!("/v1/auth/oauth/github/{path}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
  }

  #[tokio::test]
  async fn test_link_rejects_proof_of_a_different_account() {
    let account = user(UserStatus::Active, UserRole::User);
    let cfg = config();
    let other = user(UserStatus::Active, UserRole::User);
    let proof = ownership::issue(&cfg, &other).unwrap().proof_token;
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[account.clone()]])
      .into_connection();
    let state = AppState {
      db: Db { conn: db },
      cfg: cfg.clone(),
    };
    let app = super::super::router(state.clone()).with_state(state);
    let response = app
      .oneshot(
        Request::builder()
          .method("POST")
          .uri("/v1/auth/oauth/github/link")
          .header(
            "authorization",
            format!("Bearer {}", generate_token(&account, &cfg).unwrap()),
          )
          .header("content-type", "application/json")
          .body(Body::from(
            serde_json::json!({"proof_token": proof}).to_string(),
          ))
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
  }
  #[tokio::test]
  async fn test_callback_response_preserves_json_shapes_and_clears_flow() {
    let cfg = config();
    let proof = OwnershipProofResponse {
      user_id: uuid::Uuid::new_v4(),
      proof_token: "proof-token".into(),
      expires_in: 300,
    };
    let response = CallbackResponse::Proof(proof).into_callback(&cfg);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
      response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0")
    );
    let json: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(json["proof_token"], "proof-token");
    assert!(json.get("token").is_none());
    let response = CallbackResponse::Session(Box::new(AuthResponse {
      token: "access".into(),
      refresh_token: "refresh".into(),
      user: UserDto::default(),
    }))
    .into_callback(&cfg);
    let json: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(json["token"], "access");
    assert_eq!(json["refresh_token"], "refresh");
    assert!(json.get("proof_token").is_none());
  }

  #[test]
  fn test_callback_redirect_keeps_proof_in_fragment() {
    let mut cfg = config();
    std::sync::Arc::get_mut(&mut cfg)
      .unwrap()
      .oauth
      .success_redirect_url = "https://app.example.com/auth".into();
    let id = uuid::Uuid::new_v4();
    let response = CallbackResponse::Proof(OwnershipProofResponse {
      user_id: id,
      proof_token: "proof-token".into(),
      expires_in: 300,
    })
    .into_callback(&cfg);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
      response.headers()[header::LOCATION],
      format!("https://app.example.com/auth#account_proof=proof-token&user_id={id}")
    );
  }
}
