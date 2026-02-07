use axum::extract::State;
use axum::{extract::Request, middleware::Next, response::Response};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::common::errors::ApiError;
use crate::modules::users::dto::UserDto;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Claims {
  pub sub: String,
  pub exp: usize,
  pub iat: usize,
  pub user: UserDto,
}

pub async fn auth_guard(
  State(_): State<AppState>,
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

  // Get JWT secret from environment
  let secret = std::env::var("JWT_SECRET")
    .unwrap_or_else(|_| "a-string-secret-at-least-256-bits-long".to_string());

  // Decode and validate the token
  let token_data = decode::<Claims>(
    token,
    &DecodingKey::from_secret(secret.as_bytes()),
    &Validation::default(),
  )
  .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

  // Check if token is expired
  let now = chrono::Utc::now().timestamp() as usize;
  if token_data.claims.exp < now {
    return Err(ApiError::Unauthorized("Token has expired".to_string()));
  }

  // Add user role to request extensions for GraphQL context
  let mut req = req;
  req.extensions_mut().insert(UserDto {
    ..token_data.claims.user
  });

  Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
  use super::*;

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
}
