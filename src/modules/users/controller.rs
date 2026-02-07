use axum::{
  extract::{Path, Query, State},
  Json,
};
use uuid::Uuid;

use crate::common::pagination::{PaginatedResponse, PaginationParams};
use crate::common::validated_json::ValidatedJson;
use crate::modules::users::dto::{UserCreate, UserDto, UserUpdate};
use crate::{app::AppState, common::api_error::ApiError, modules::users::service};

#[utoipa::path(
  get,
  tag = "Users",
  path = "/api/v1/users",
  operation_id = "usersIndex",
  params(PaginationParams),
  responses(
      (status = 200, description = "List users (page mode or cursor mode)")
  ),
  security(
    ("bearerAuth" = [])
  )
)]
pub async fn index(
  State(state): State<AppState>,
  Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<UserDto>>, ApiError> {
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
) -> Result<Json<UserDto>, ApiError> {
  let result = service::create(&state.db.conn, user.email, user.password, user.name).await?;
  Ok(Json(result))
}

#[utoipa::path(
  get,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersShow",
  params(
    ("user_id" = String, Path, description = "User ID (UUID format)")
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
  Path(user_id): Path<Uuid>,
) -> Result<Json<UserDto>, ApiError> {
  let result = service::show(&state.db.conn, user_id).await?;
  Ok(Json(result))
}

#[utoipa::path(
  put,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersUpdate",
  params(
    ("user_id" = String, Path, description = "User ID (UUID format)")
  ),
  request_body = UserUpdate,
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
  Path(user_id): Path<Uuid>,
  ValidatedJson(user): ValidatedJson<UserUpdate>,
) -> Result<Json<UserDto>, ApiError> {
  let result = service::update(&state.db.conn, user_id, user.name).await?;
  Ok(Json(result))
}

#[utoipa::path(
  delete,
  tag = "Users",
  path = "/api/v1/users/{user_id}",
  operation_id = "usersDestroy",
  params(
    ("user_id" = String, Path, description = "User ID (UUID format)")
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
  Path(user_id): Path<Uuid>,
) -> Result<(), ApiError> {
  service::destroy(&state.db.conn, user_id).await
}
