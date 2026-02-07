use axum::{extract::State, Json};

use crate::app::AppState;
use crate::common::api_error::ApiError;
use crate::common::validation::ValidatedJson;
use crate::modules::auth::dto::{AuthResponse, LoginRequest, RegisterRequest};
use crate::modules::auth::service;

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
