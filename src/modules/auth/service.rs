use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{hash, verify};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::RngExt;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
  QueryOrder, Set, TransactionTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::modules::auth::dto::{
  AuthResponse, LoginRequest, LogoutResponse, RefreshRequest, RegisterRequest, SessionDto,
  TokenPairResponse,
};
use crate::modules::auth::entities::{self as RefreshTokenEntities};
use crate::modules::auth::guards::auth_guard::Claims;
use crate::modules::users::dto::UserDto;
use crate::modules::users::entities::{self as UserEntities};

/// Number of random bytes behind a refresh token.
const REFRESH_TOKEN_BYTES: usize = 32;

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

  let token = generate_token(&user, cfg)?;
  let refresh_token = issue_refresh_token(conn, cfg, user.id).await?;

  Ok(AuthResponse {
    token,
    refresh_token,
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

  let token = generate_token(&user, cfg)?;
  let refresh_token = issue_refresh_token(conn, cfg, user.id).await?;

  Ok(AuthResponse {
    token,
    refresh_token,
    user: UserDto::from(user),
  })
}

/// Exchanges a refresh token for a new pair, revoking the presented one.
///
/// Rotation happens in a transaction with the revocation of the old token, so a
/// token can never be spent twice.
pub async fn refresh(
  conn: &DatabaseConnection,
  cfg: &Config,
  req: RefreshRequest,
) -> Result<TokenPairResponse, ApiError> {
  let txn = conn.begin().await?;

  let stored = RefreshTokenEntities::Entity::find()
    .filter(RefreshTokenEntities::Column::TokenHash.eq(hash_token(&req.refresh_token)))
    .one(&txn)
    .await?
    .filter(RefreshTokenEntities::Model::is_usable)
    .ok_or_else(|| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

  let user = UserEntities::Entity::find_by_id(stored.user_id)
    .one(&txn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

  let mut revoked: RefreshTokenEntities::ActiveModel = stored.into();
  revoked.revoked_at = Set(Some(Utc::now()));
  revoked.update(&txn).await?;

  let token = generate_token(&user, cfg)?;
  let refresh_token = issue_refresh_token(&txn, cfg, user.id).await?;

  txn.commit().await?;

  Ok(TokenPairResponse {
    token,
    refresh_token,
  })
}

/// Revokes a single refresh token.
///
/// Revoking an unknown or already revoked token succeeds with a count of zero,
/// so a client cannot probe which tokens exist.
pub async fn logout(
  conn: &DatabaseConnection,
  req: RefreshRequest,
) -> Result<LogoutResponse, ApiError> {
  let result = RefreshTokenEntities::Entity::update_many()
    .col_expr(
      RefreshTokenEntities::Column::RevokedAt,
      sea_orm::sea_query::Expr::value(Utc::now()),
    )
    .filter(RefreshTokenEntities::Column::TokenHash.eq(hash_token(&req.refresh_token)))
    .filter(RefreshTokenEntities::Column::RevokedAt.is_null())
    .exec(conn)
    .await?;

  Ok(LogoutResponse {
    revoked: result.rows_affected,
  })
}

/// Revokes every refresh token of a user, ending all of their sessions.
pub async fn logout_all(
  conn: &DatabaseConnection,
  user_id: Uuid,
) -> Result<LogoutResponse, ApiError> {
  let result = RefreshTokenEntities::Entity::update_many()
    .col_expr(
      RefreshTokenEntities::Column::RevokedAt,
      sea_orm::sea_query::Expr::value(Utc::now()),
    )
    .filter(RefreshTokenEntities::Column::UserId.eq(user_id))
    .filter(RefreshTokenEntities::Column::RevokedAt.is_null())
    .exec(conn)
    .await?;

  Ok(LogoutResponse {
    revoked: result.rows_affected,
  })
}

/// Lists the logins of a user, most recent first.
pub async fn sessions(
  conn: &DatabaseConnection,
  user_id: Uuid,
) -> Result<Vec<SessionDto>, ApiError> {
  let tokens = RefreshTokenEntities::Entity::find()
    .filter(RefreshTokenEntities::Column::UserId.eq(user_id))
    .order_by_desc(RefreshTokenEntities::Column::CreatedAt)
    .all(conn)
    .await?;

  Ok(tokens.into_iter().map(SessionDto::from).collect())
}

/// Deletes refresh tokens that can no longer be used.
///
/// Revoked tokens outlive their revocation by the retention window, so a
/// rotated token that resurfaces is still recognisable for that long.
pub async fn cleanup_tokens(
  conn: &DatabaseConnection,
  retention_days: i64,
) -> Result<u64, ApiError> {
  let now = Utc::now();
  let retention_cutoff = now - chrono::Duration::days(retention_days);

  let result = RefreshTokenEntities::Entity::delete_many()
    .filter(
      Condition::any()
        .add(RefreshTokenEntities::Column::ExpiresAt.lt(now))
        .add(RefreshTokenEntities::Column::RevokedAt.lt(retention_cutoff)),
    )
    .exec(conn)
    .await?;

  Ok(result.rows_affected)
}

/// Stores a freshly generated refresh token and returns its plaintext, which is
/// the only moment the plaintext exists.
pub(crate) async fn issue_refresh_token<C>(
  conn: &C,
  cfg: &Config,
  user_id: Uuid,
) -> Result<String, ApiError>
where
  C: sea_orm::ConnectionTrait,
{
  let token = generate_refresh_token();
  let expires_at = Utc::now()
    .checked_add_signed(chrono::Duration::days(cfg.jwt_refresh_expiration_days))
    .ok_or_else(|| ApiError::InternalError(anyhow!("Invalid refresh token expiration")))?;

  RefreshTokenEntities::ActiveModel {
    id: Set(Uuid::new_v4()),
    user_id: Set(user_id),
    token_hash: Set(hash_token(&token)),
    expires_at: Set(expires_at),
    revoked_at: Set(None),
    ..Default::default()
  }
  .insert(conn)
  .await?;

  Ok(token)
}

fn generate_refresh_token() -> String {
  let bytes: [u8; REFRESH_TOKEN_BYTES] = rand::rng().random();
  URL_SAFE_NO_PAD.encode(bytes)
}

/// Refresh tokens are random secrets rather than passwords, so a plain digest is
/// enough to keep the database from holding usable credentials.
fn hash_token(token: &str) -> String {
  let digest = Sha256::digest(token.as_bytes());
  digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub(crate) fn generate_token(user: &UserEntities::Model, cfg: &Config) -> Result<String, ApiError> {
  let secret = cfg.jwt_secret.expose();
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
