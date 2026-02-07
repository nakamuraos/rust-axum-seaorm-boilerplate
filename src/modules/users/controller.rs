use axum::{
  extract::{Path, Query, State},
  Json,
};
use serde_json::Value;
use uuid::Uuid;

use crate::common::pagination::PaginationParams;
use crate::common::validated_json::ValidatedJson;
use crate::modules::users::dto::UserCreate;
use crate::{app::AppState, modules::users::dto::UserDto};
use crate::{common::api_error::ApiError, modules::users::service};

#[utoipa::path(
  get,
  tag = "Users",
  path = "/api/v1/users",
  operation_id = "usersIndex",
  params(PaginationParams),
  responses(
      (status = 200, description = "List users (page mode or cursor mode)", body = Value)
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn index(
  State(state): State<AppState>,
  Query(params): Query<PaginationParams>,
) -> Result<Json<Value>, ApiError> {
  let result = service::index(&state.db.conn, &params).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Users",
  path = "/api/v1/users",
  operation_id = "usersCreate",
  request_body = UserCreate,
  responses(
      (status = 200, description = "Create a user", body = UserDto)
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn create(
  State(state): State<AppState>,
  ValidatedJson(user): ValidatedJson<UserCreate>,
) -> Result<Json<Value>, ApiError> {
  let result = service::create(&state.db.conn, user.email, user.password, user.name).await?;
  Ok(Json(result))
}

#[utoipa::path(
  get,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersShow",
  params(
    ("user_id" = String, Path, description = "User ID")
  ),
  responses(
    (status = 200, description = "Get user details", body = UserDto),
    (status = 404, description = "User not found")
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn show(
  State(state): State<AppState>,
  Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
  let id = Uuid::parse_str(&user_id)
    .map_err(|_| ApiError::InvalidRequest("Invalid user ID".to_string()))?;
  let result = service::show(&state.db.conn, id).await?;
  Ok(Json(result))
}

#[utoipa::path(
  put,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersUpdate",
  params(
    ("user_id" = String, Path, description = "User ID")
  ),
  request_body = UserCreate,
  responses(
    (status = 200, description = "Update user", body = UserDto),
    (status = 404, description = "User not found")
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn update(
  State(state): State<AppState>,
  Path(user_id): Path<String>,
  ValidatedJson(user): ValidatedJson<UserCreate>,
) -> Result<Json<Value>, ApiError> {
  let id = Uuid::parse_str(&user_id)
    .map_err(|_| ApiError::InvalidRequest("Invalid user ID".to_string()))?;
  let result = service::update(&state.db.conn, id, user.name).await?;
  Ok(Json(result))
}

#[utoipa::path(
  delete,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersDestroy",
  params(
    ("user_id" = String, Path, description = "User ID")
  ),
  responses(
    (status = 204, description = "User deleted successfully"),
    (status = 404, description = "User not found")
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn destroy(
  State(state): State<AppState>,
  Path(user_id): Path<String>,
) -> Result<(), ApiError> {
  let id = Uuid::parse_str(&user_id)
    .map_err(|_| ApiError::InvalidRequest("Invalid user ID".to_string()))?;
  service::destroy(&state.db.conn, id).await
}
