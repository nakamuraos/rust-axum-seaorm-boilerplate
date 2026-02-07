use anyhow::anyhow;
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::common::api_error::ApiError;
use crate::common::cfg::Config;
use crate::modules::auth::dto::{AuthResponse, LoginRequest, RegisterRequest};
use crate::modules::auth::guards::auth_guard::Claims;
use crate::modules::users::dto::UserDto;
use crate::modules::users::entities::{self as UserEntities};

pub async fn register(
  conn: &DatabaseConnection,
  cfg: &Config,
  req: RegisterRequest,
) -> Result<AuthResponse, ApiError> {
  // Hash password
  let password_hash = hash(req.password.as_bytes(), cfg.bcrypt_cost)
    .map_err(|e| ApiError::InternalError(anyhow!("Failed to hash password: {}", e)))?;

  // Create user
  let user = UserEntities::ActiveModel {
    id: sea_orm::ActiveValue::Set(Uuid::new_v4()),
    email: sea_orm::ActiveValue::Set(req.email),
    password: sea_orm::ActiveValue::Set(password_hash),
    name: sea_orm::ActiveValue::Set(req.name),
    ..Default::default()
  };

  let user = user.insert(conn).await.map_err(|e| {
    if e.to_string().contains("duplicate key") {
      ApiError::InvalidRequest("Email already exists".to_string())
    } else {
      ApiError::InternalError(anyhow!(e))
    }
  })?;

  // Generate JWT token
  let token = generate_token(&user, cfg)?;

  Ok(AuthResponse {
    token,
    user: UserDto::from(user),
  })
}

pub async fn login(
  conn: &DatabaseConnection,
  cfg: &Config,
  req: LoginRequest,
) -> Result<AuthResponse, ApiError> {
  // Find user by email
  let user = UserEntities::Entity::find()
    .filter(UserEntities::Column::Email.eq(req.email))
    .one(conn)
    .await?
    .ok_or_else(|| ApiError::InvalidRequest("Invalid credentials".to_string()))?;

  // Verify password
  if !verify(req.password, &user.password)
    .map_err(|e| ApiError::InternalError(anyhow!("Failed to verify password: {}", e)))?
  {
    return Err(ApiError::InvalidRequest("Invalid credentials".to_string()));
  }

  // Generate JWT token
  let token = generate_token(&user, cfg)?;

  Ok(AuthResponse {
    token,
    user: UserDto::from(user),
  })
}

fn generate_token(user: &UserEntities::Model, cfg: &Config) -> Result<String, ApiError> {
  let secret = std::env::var("JWT_SECRET")
    .unwrap_or_else(|_| "a-string-secret-at-least-256-bits-long".to_string());
  let expiration = chrono::Utc::now()
    .checked_add_signed(chrono::Duration::days(cfg.jwt_expiration_days))
    .expect("valid timestamp")
    .timestamp();

  let claims = Claims {
    sub: user.id.to_string(),
    exp: expiration as usize,
    user: user.clone().into(),
    ..Default::default()
  };

  encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
  )
  .map_err(|e| ApiError::InternalError(anyhow!("Failed to generate token: {}", e)))
}
