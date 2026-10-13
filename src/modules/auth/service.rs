pub(crate) mod accounts;
pub(crate) mod ownership;
pub(crate) mod password;

use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::RngExt;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
  QueryOrder, QuerySelect, Set, TransactionTrait,
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
use crate::modules::users::enums::UserStatus;

/// Number of random bytes behind a refresh token.
const REFRESH_TOKEN_BYTES: usize = 32;

pub async fn register(
  conn: &DatabaseConnection,
  cfg: &Config,
  req: RegisterRequest,
) -> Result<AuthResponse, ApiError> {
  // Hash password
  let password_hash = password::hash(req.password, cfg.bcrypt_cost).await?;

  // Create user
  let user = UserEntities::ActiveModel {
    id: sea_orm::ActiveValue::Set(Uuid::new_v4()),
    email: sea_orm::ActiveValue::Set(req.email),
    password: sea_orm::ActiveValue::Set(password_hash),
    name: sea_orm::ActiveValue::Set(req.name),
    status: Set(UserStatus::Active),
    ..Default::default()
  };

  let user = user.insert(conn).await.map_err(|e| {
    if e.to_string().contains("duplicate key") {
      ApiError::InvalidRequest("Email already exists".to_string())
    } else {
      ApiError::InternalError(anyhow!(e))
    }
  })?;

  open_session(conn, cfg, user).await
}

pub async fn login(
  conn: &DatabaseConnection,
  cfg: &Config,
  req: LoginRequest,
) -> Result<AuthResponse, ApiError> {
  let verified = UserEntities::Entity::find()
    .filter(UserEntities::Column::Email.eq(req.email))
    .one(conn)
    .await?
    .ok_or_else(|| ApiError::InvalidRequest("Invalid credentials".into()))?;
  ensure_active(&verified.status)?;
  if !password::verify(req.password, verified.password.clone()).await? {
    return Err(ApiError::InvalidRequest("Invalid credentials".into()));
  }

  let txn = conn.begin().await?;
  // Credential work runs before locking; session issuance uses the current account state.
  let user = UserEntities::Entity::find_by_id(verified.id)
    .lock_exclusive()
    .one(&txn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".into()))?;
  ensure_active(&user.status)?;
  if user.password != verified.password {
    return Err(ApiError::Unauthorized(
      "Account credentials have changed".into(),
    ));
  }
  let auth = open_session(&txn, cfg, user).await?;
  txn.commit().await?;
  Ok(auth)
}

pub(crate) async fn open_session<C: sea_orm::ConnectionTrait>(
  conn: &C,
  cfg: &Config,
  user: UserEntities::Model,
) -> Result<AuthResponse, ApiError> {
  ensure_active(&user.status)?;
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
/// A conditional revocation and the replacement token commit together.
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
    .lock_exclusive()
    .one(&txn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

  ensure_active(&user.status)?;

  // The conditional write lets exactly one transaction consume the token.
  let now = Utc::now();
  let revoked = RefreshTokenEntities::Entity::update_many()
    .col_expr(
      RefreshTokenEntities::Column::RevokedAt,
      sea_orm::sea_query::Expr::value(now),
    )
    .filter(RefreshTokenEntities::Column::Id.eq(stored.id))
    .filter(RefreshTokenEntities::Column::RevokedAt.is_null())
    .filter(RefreshTokenEntities::Column::ExpiresAt.gt(now))
    .exec(&txn)
    .await?;
  if revoked.rows_affected != 1 {
    return Err(ApiError::Unauthorized("Invalid refresh token".to_string()));
  }

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

pub(crate) fn ensure_active(status: &UserStatus) -> Result<(), ApiError> {
  if *status != UserStatus::Active {
    return Err(ApiError::Forbidden("Account is not active".to_string()));
  }
  Ok(())
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
    iat: Utc::now().timestamp() as usize,
    session_version: user.session_version,
    user: user.clone().into(),
  };

  encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
  )
  .map_err(|e| ApiError::InternalError(anyhow!("Failed to generate token: {}", e)))
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::modules::users::{
    entities,
    enums::{UserRole, UserStatus},
  };
  use sea_orm::{DbBackend, MockDatabase};
  pub(crate) fn refresh_token(user_id: Uuid) -> RefreshTokenEntities::Model {
    RefreshTokenEntities::Model {
      id: Uuid::new_v4(),
      user_id,
      token_hash: hash_token("refresh-secret"),
      expires_at: Utc::now() + chrono::Duration::days(1),
      revoked_at: None,
      created_at: Utc::now(),
    }
  }

  pub(crate) fn user(status: UserStatus, role: UserRole) -> entities::Model {
    entities::Model {
      id: Uuid::new_v4(),
      email: "victim@example.com".into(),
      name: "Victim".into(),
      password: bcrypt::hash("attacker-known-password", 4).unwrap(),
      phone: None,
      bio: None,
      status,
      role,
      session_version: 0,
      merged_into: None,
      merged_at: None,
      created_at: Utc::now(),
      updated_at: Utc::now(),
    }
  }

  #[tokio::test]
  async fn security_password_login_rejects_banned_user() {
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[user(UserStatus::Banned, UserRole::User)]])
      .append_query_results([[refresh_token(Uuid::new_v4())]])
      .into_connection();
    let result = login(
      &db,
      &config(),
      LoginRequest {
        email: "victim@example.com".into(),
        password: "attacker-known-password".into(),
      },
    )
    .await;
    assert!(
      matches!(
        result,
        Err(ApiError::Unauthorized(_) | ApiError::Forbidden(_))
      ),
      "Banned login must be rejected before issuing a session: {result:?}"
    );
  }

  #[tokio::test]
  async fn security_active_password_login_succeeds() {
    let user = user(UserStatus::Active, UserRole::User);
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[user.clone()]])
      .append_query_results([[user.clone()]])
      .append_query_results([[refresh_token(user.id)]])
      .into_connection();
    let result = login(
      &db,
      &config(),
      LoginRequest {
        email: user.email,
        password: "attacker-known-password".into(),
      },
    )
    .await
    .unwrap();
    assert_eq!(result.user.id, user.id.to_string());
    assert!(!result.refresh_token.is_empty());
  }

  #[tokio::test]
  async fn security_wrong_password_is_rejected() {
    let user = user(UserStatus::Active, UserRole::User);
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[user.clone()]])
      .into_connection();
    let result = login(
      &db,
      &config(),
      LoginRequest {
        email: user.email,
        password: "wrong-password".into(),
      },
    )
    .await;
    assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
  }

  #[tokio::test]
  async fn security_refresh_rejects_inactive_accounts() {
    for status in [UserStatus::Banned, UserStatus::Inactive] {
      let user = user(status, UserRole::User);
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[refresh_token(user.id)]])
        .append_query_results([[user]])
        .into_connection();
      let result = refresh(
        &db,
        &config(),
        RefreshRequest {
          refresh_token: "refresh-secret".into(),
        },
      )
      .await;
      assert!(matches!(result, Err(ApiError::Forbidden(_))));
    }
  }

  #[tokio::test]
  async fn security_refresh_rejects_expired_and_revoked_tokens() {
    for expired in [true, false] {
      let mut stored = refresh_token(Uuid::new_v4());
      if expired {
        stored.expires_at = Utc::now() - chrono::Duration::seconds(1);
      } else {
        stored.revoked_at = Some(Utc::now());
      }
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[stored]])
        .into_connection();
      let result = refresh(
        &db,
        &config(),
        RefreshRequest {
          refresh_token: "refresh-secret".into(),
        },
      )
      .await;
      assert!(matches!(result, Err(ApiError::Unauthorized(_))));
    }
  }

  #[tokio::test]
  async fn security_refresh_requires_successful_consumption() {
    for rows_affected in [0, 1] {
      let user = user(UserStatus::Active, UserRole::User);
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[refresh_token(user.id)]])
        .append_query_results([[user.clone()]])
        .append_exec_results([sea_orm::MockExecResult {
          last_insert_id: 0,
          rows_affected,
        }])
        .append_query_results([[refresh_token(user.id)]])
        .into_connection();
      let result = refresh(
        &db,
        &config(),
        RefreshRequest {
          refresh_token: "refresh-secret".into(),
        },
      )
      .await;
      if rows_affected == 0 {
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
      } else {
        let pair = result.unwrap();
        assert_ne!(pair.refresh_token, "refresh-secret");
        assert!(!pair.token.is_empty());
      }
    }
  }

  #[tokio::test]
  #[ignore = "Requires SECURITY_TEST_DATABASE_URL pointing to an isolated PostgreSQL database"]
  async fn security_concurrent_refresh_has_one_winner() {
    use sea_orm_migration::MigratorTrait;
    let url = std::env::var("SECURITY_TEST_DATABASE_URL")
      .expect("An isolated PostgreSQL database is required");
    let db = sea_orm::Database::connect(url).await.unwrap();
    crate::database::migrations::Migrator::up(&db, None)
      .await
      .unwrap();
    let cfg = config();
    let registered = register(
      &db,
      &cfg,
      RegisterRequest {
        email: format!("{}@example.com", Uuid::new_v4()),
        name: "Concurrent refresh user".into(),
        password: "test-password".into(),
      },
    )
    .await
    .unwrap();
    assert_eq!(registered.user.status, "Active");
    let user_id = Uuid::parse_str(&registered.user.id).unwrap();
    let secret = registered.refresh_token;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
      let (db, cfg, barrier, secret) = (db.clone(), cfg.clone(), barrier.clone(), secret.clone());
      tasks.spawn(async move {
        barrier.wait().await;
        refresh(
          &db,
          &cfg,
          RefreshRequest {
            refresh_token: secret,
          },
        )
        .await
      });
    }
    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
      match result.unwrap() {
        Ok(_) => successes += 1,
        Err(ApiError::Unauthorized(_)) => {}
        Err(error) => panic!("Unexpected refresh failure: {error}"),
      }
    }
    UserEntities::Entity::delete_by_id(user_id)
      .exec(&db)
      .await
      .unwrap();
    assert_eq!(successes, 1);
  }
  #[tokio::test]
  async fn security_login_rechecks_account_after_password_verification() {
    for scenario in 0..3 {
      let verified = user(UserStatus::Active, UserRole::User);
      let mut current = verified.clone();
      match scenario {
        0 => current.status = UserStatus::Merged,
        1 => current.password = "changed-password-hash".into(),
        _ => current.session_version += 1,
      }
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[verified.clone()]])
        .append_query_results([[current.clone()]])
        .append_query_results([[refresh_token(current.id)]])
        .into_connection();
      let result = login(
        &db,
        &config(),
        LoginRequest {
          email: verified.email,
          password: "attacker-known-password".into(),
        },
      )
      .await;
      if scenario == 2 {
        let claims = jsonwebtoken::decode::<Claims>(
          &result.unwrap().token,
          &jsonwebtoken::DecodingKey::from_secret(config().jwt_secret.expose().as_bytes()),
          &jsonwebtoken::Validation::default(),
        )
        .unwrap()
        .claims;
        assert_eq!(claims.session_version, current.session_version);
      } else {
        assert!(matches!(
          result,
          Err(ApiError::Unauthorized(_) | ApiError::Forbidden(_))
        ));
      }
    }
  }
}
