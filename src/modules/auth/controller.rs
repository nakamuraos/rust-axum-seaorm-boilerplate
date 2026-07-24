use axum::{Extension, Json, extract::State};

use crate::app::AppState;
use crate::common::errors::ApiError;
use crate::common::extractors::ValidatedJson;
use crate::modules::auth::dto::{
  AuthResponse, LoginRequest, LogoutResponse, RefreshRequest, RegisterRequest, SessionDto,
  TokenPairResponse,
};
use crate::modules::auth::service;
use crate::modules::users::dto::UserDto;

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/register",
  operation_id = "authRegister",
  request_body = RegisterRequest,
  responses(
    (status = 200, description = "Register successful", body = AuthResponse),
    (status = 400, description = "Validation error"),
    (status = 409, description = "Email already exists"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn register(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
  let result = service::register(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/login",
  operation_id = "authLogin",
  request_body = LoginRequest,
  responses(
    (status = 200, description = "Login successful", body = AuthResponse),
    (status = 400, description = "Validation error"),
    (status = 401, description = "Invalid credentials"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn login(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
  let result = service::login(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/refresh",
  operation_id = "authRefresh",
  request_body = RefreshRequest,
  responses(
    (status = 200, description = "New token pair issued", body = TokenPairResponse),
    (status = 400, description = "Validation error"),
    (status = 401, description = "Invalid or expired refresh token"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn refresh(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<TokenPairResponse>, ApiError> {
  let result = service::refresh(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/logout",
  operation_id = "authLogout",
  request_body = RefreshRequest,
  responses(
    (status = 200, description = "Refresh token revoked", body = LogoutResponse),
    (status = 400, description = "Validation error"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn logout(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<LogoutResponse>, ApiError> {
  let result = service::logout(&state.db.conn, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/logout-all",
  operation_id = "authLogoutAll",
  security(("bearer_auth" = [])),
  responses(
    (status = 200, description = "All refresh tokens revoked", body = LogoutResponse),
    (status = 401, description = "Unauthorized"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn logout_all(
  State(state): State<AppState>,
  Extension(user): Extension<UserDto>,
) -> Result<Json<LogoutResponse>, ApiError> {
  let user_id = user
    .id
    .parse()
    .map_err(|_| ApiError::Unauthorized("Invalid user id in token".to_string()))?;
  let result = service::logout_all(&state.db.conn, user_id).await?;
  Ok(Json(result))
}

#[utoipa::path(
  get,
  tag = "Auth",
  path = "/api/v1/auth/sessions",
  operation_id = "authSessions",
  security(("bearer_auth" = [])),
  responses(
    (status = 200, description = "Logins of the authenticated user", body = Vec<SessionDto>),
    (status = 401, description = "Unauthorized"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn sessions(
  State(state): State<AppState>,
  Extension(user): Extension<UserDto>,
) -> Result<Json<Vec<SessionDto>>, ApiError> {
  let user_id = user
    .id
    .parse()
    .map_err(|_| ApiError::Unauthorized("Invalid user id in token".to_string()))?;
  let result = service::sessions(&state.db.conn, user_id).await?;
  Ok(Json(result))
}
