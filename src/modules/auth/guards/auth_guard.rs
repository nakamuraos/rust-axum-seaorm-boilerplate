use axum::extract::State;
use axum::{extract::Request, middleware::Next, response::Response};
use jsonwebtoken::{DecodingKey, Validation, decode};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::common::errors::ApiError;
use crate::modules::auth::service::ensure_active;
use crate::modules::users::{
  dto::UserDto,
  entities::{Entity, UserProfile},
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Claims {
  pub sub: String,
  pub exp: usize,
  pub iat: usize,
  #[serde(default)]
  pub session_version: i64,
  pub user: UserDto,
}

pub async fn auth_guard(
  State(state): State<AppState>,
  req: Request,
  next: Next,
) -> Result<Response, ApiError> {
  // Get the authorization header
  let auth_header = req
    .headers()
    .get("authorization")
    .ok_or_else(|| ApiError::Unauthorized("Missing authorization header".to_string()))?
    .to_str()
    .map_err(|_| ApiError::Unauthorized("Invalid authorization header".to_string()))?;

  // Check if it's a Bearer token
  let token = auth_header
    .strip_prefix("Bearer ")
    .ok_or_else(|| ApiError::Unauthorized("Invalid authorization format".to_string()))?;

  // Decode and validate the token
  let token_data = decode::<Claims>(
    token,
    &DecodingKey::from_secret(state.cfg.jwt_secret.expose().as_bytes()),
    &Validation::default(),
  )
  .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

  // Check if token is expired
  let now = chrono::Utc::now().timestamp() as usize;
  if token_data.claims.exp < now {
    return Err(ApiError::Unauthorized("Token has expired".to_string()));
  }

  let user_id = Uuid::parse_str(&token_data.claims.sub)
    .map_err(|_| ApiError::Unauthorized("Invalid token subject".to_string()))?;
  let user = Entity::find_by_id(user_id)
    .into_partial_model::<UserProfile>()
    .one(&state.db.conn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".to_string()))?;
  ensure_active(&user.status)?;
  if user.session_version != token_data.claims.session_version {
    return Err(ApiError::Unauthorized(
      "Session has been revoked".to_string(),
    ));
  }

  let mut req = req;
  req.extensions_mut().insert(UserDto::from(user));

  Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::database::Db;
  use crate::modules::auth::{guards::admin_guard, service, service::tests::user};
  use crate::modules::users::enums::{UserRole, UserStatus};
  use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
  };
  use sea_orm::{DbBackend, MockDatabase};
  use tower::ServiceExt;

  #[test]
  fn test_claims_default() {
    let claims = Claims::default();
    assert_eq!(claims.sub, "");
    assert_eq!(claims.exp, 0);
    assert_eq!(claims.iat, 0);
  }

  #[test]
  fn test_claims_serialization() {
    let claims = Claims {
      sub: "user-123".to_string(),
      exp: 1234567890,
      iat: 1234567800,
      session_version: 0,
      user: UserDto::default(),
    };

    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("\"sub\":\"user-123\""));
    assert!(json.contains("\"exp\":1234567890"));
    assert!(json.contains("\"iat\":1234567800"));
  }

  #[test]
  fn test_claims_deserialization() {
    let json = r#"{"sub":"user-456","exp":9999999999,"iat":9999999900,"user":{"id":"00000000-0000-0000-0000-000000000000","email":"","name":"","role":"User","status":"Inactive","created_at":"1970-01-01T00:00:00Z","updated_at":"1970-01-01T00:00:00Z"}}"#;
    let claims: Claims = serde_json::from_str(json).unwrap();
    assert_eq!(claims.sub, "user-456");
    assert_eq!(claims.exp, 9999999999);
    assert_eq!(claims.iat, 9999999900);
  }
  async fn admin_response(
    current: Option<crate::modules::users::entities::Model>,
    claims: crate::modules::users::entities::Model,
  ) -> StatusCode {
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([current.into_iter().collect::<Vec<_>>()])
      .into_connection();
    let cfg = config();
    let token = service::generate_token(&claims, &cfg).unwrap();
    let state = AppState {
      db: Db { conn: db },
      cfg,
    };
    let app = Router::new()
      .route("/admin", get(|| async { StatusCode::OK }))
      .layer(axum::middleware::from_fn(admin_guard))
      .layer(axum::middleware::from_fn_with_state(state, auth_guard));
    app
      .oneshot(
        Request::builder()
          .uri("/admin")
          .header("authorization", format!("Bearer {token}"))
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap()
      .status()
  }

  #[tokio::test]
  async fn security_admin_access_rechecks_current_role() {
    let current = user(UserStatus::Active, UserRole::User);
    let mut claims = current.clone();
    claims.role = UserRole::Admin;
    assert_eq!(
      admin_response(Some(current), claims).await,
      StatusCode::FORBIDDEN
    );
  }

  #[tokio::test]
  async fn security_admin_access_accepts_current_admin() {
    let current = user(UserStatus::Active, UserRole::Admin);
    assert_eq!(
      admin_response(Some(current.clone()), current).await,
      StatusCode::OK
    );
  }

  #[tokio::test]
  async fn security_access_rejects_banned_and_deleted_accounts() {
    let claims = user(UserStatus::Active, UserRole::Admin);
    let mut current = claims.clone();
    current.status = UserStatus::Banned;
    assert_eq!(
      admin_response(Some(current), claims.clone()).await,
      StatusCode::FORBIDDEN
    );
    assert_eq!(admin_response(None, claims).await, StatusCode::UNAUTHORIZED);
  }
  #[tokio::test]
  async fn security_access_rejects_revoked_session_and_merged_account() {
    let claims = user(UserStatus::Active, UserRole::Admin);
    let mut current = claims.clone();
    current.session_version += 1;
    assert_eq!(
      admin_response(Some(current), claims.clone()).await,
      StatusCode::UNAUTHORIZED
    );
    let mut current = claims.clone();
    current.status = UserStatus::Merged;
    assert_eq!(
      admin_response(Some(current), claims).await,
      StatusCode::FORBIDDEN
    );
  }
}
