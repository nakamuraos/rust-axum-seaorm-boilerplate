use axum::{extract::Request, middleware::Next, response::Response};
use sea_orm::ActiveEnum;

use crate::common::api_error::ApiError;
use crate::modules::users::dto::UserDto;
use crate::modules::users::enums::UserRole;

/// Middleware that allows access if the user is an admin OR is accessing their own resource.
///
/// Extracts `user_id` from the path (e.g. `/users/{user_id}`) and compares it
/// to the authenticated user's ID. Admins bypass the check entirely.
pub async fn admin_or_owner_guard(req: Request, next: Next) -> Result<Response, ApiError> {
  let user = req
    .extensions()
    .get::<UserDto>()
    .ok_or_else(|| ApiError::Unauthorized("User not found in request".to_string()))?
    .clone();

  // Admins can access any resource
  if user.role == UserRole::Admin.to_value() {
    return Ok(next.run(req).await);
  }

  // Extract user_id from the path
  let path = req.uri().path().to_string();
  let path_user_id = path
    .rsplit('/')
    .next()
    .ok_or_else(|| ApiError::Forbidden("Access denied".to_string()))?;

  // Check if the authenticated user is the resource owner
  if user.id == path_user_id {
    return Ok(next.run(req).await);
  }

  Err(ApiError::Forbidden(
    "You can only access your own resource".to_string(),
  ))
}
