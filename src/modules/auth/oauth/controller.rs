use super::{
  dto::{AuthorizationResponse, CallbackQuery, CallbackResponse},
  service,
};
use crate::app::AppState;
use crate::common::{errors::ApiError, extractors::ValidatedJson};
use crate::modules::auth::dto::LinkIdentityRequest;
use axum::{
  Extension,
  extract::{Path, Query, State},
  http::{HeaderMap, header},
  response::{IntoResponse, Response},
};
use uuid::Uuid;

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
  Ok(service::login(&state.cfg, &provider).await?.into_response())
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
  let cookie = headers
    .get(header::COOKIE)
    .and_then(|value| value.to_str().ok());
  Ok(
    service::callback(&state.db.conn, &state.cfg, &provider, query, cookie)
      .await?
      .into_callback(&state.cfg),
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
  Extension(user_id): Extension<Uuid>,
  ValidatedJson(req): ValidatedJson<LinkIdentityRequest>,
) -> Result<Response, ApiError> {
  Ok(
    service::link(&state.cfg, user_id, &provider, req)
      .await?
      .into_response(),
  )
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
  Extension(user_id): Extension<Uuid>,
) -> Result<Response, ApiError> {
  Ok(
    service::verify(&state.db.conn, &state.cfg, user_id, &provider)
      .await?
      .into_response(),
  )
}

#[cfg(test)]
mod tests {
  use super::super::flow::{Flow, Intent};
  use super::*;
  use crate::common::config::{Secret, tests::config};
  use crate::database::Db;
  use crate::modules::auth::{
    service::ownership,
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
}
