use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::hash;
use rand::RngExt;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
  TransactionTrait,
};
use uuid::Uuid;

use super::Profile;
use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::modules::auth::dto::AuthResponse;
use crate::modules::auth::entities::identity;
use crate::modules::auth::service::{generate_token, issue_refresh_token};
use crate::modules::users::dto::UserDto;
use crate::modules::users::entities::{self as UserEntities};
use crate::modules::users::enums::UserStatus;

/// Finds or creates the user behind a provider account and opens a session.
///
/// A known `(provider, subject)` always wins. Otherwise the account is linked
/// to the user with the same email, or a new user is created; both require the
/// provider to vouch for the email, since linking on an unverified address
/// would let anyone take over an account by registering its email elsewhere.
pub async fn sign_in(
  conn: &DatabaseConnection,
  cfg: &Config,
  provider: &str,
  profile: Profile,
) -> Result<AuthResponse, ApiError> {
  let txn = conn.begin().await?;

  let linked = identity::Entity::find()
    .filter(identity::Column::Provider.eq(provider))
    .filter(identity::Column::Subject.eq(profile.subject.as_str()))
    .one(&txn)
    .await?;

  let user = match linked {
    Some(identity) => UserEntities::Entity::find_by_id(identity.user_id)
      .one(&txn)
      .await?
      .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".to_string()))?,
    None => {
      let email = profile
        .email
        .as_deref()
        .filter(|_| profile.email_verified)
        .ok_or_else(|| {
          ApiError::Unauthorized("The provider did not return a verified email".to_string())
        })?;

      let existing = UserEntities::Entity::find()
        .filter(UserEntities::Column::Email.eq(email))
        .one(&txn)
        .await?;

      let user = match existing {
        Some(user) => user,
        None => create_user(&txn, cfg, email, profile.name.as_deref()).await?,
      };

      identity::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        provider: Set(provider.to_string()),
        subject: Set(profile.subject),
        ..Default::default()
      }
      .insert(&txn)
      .await?;

      user
    }
  };

  let token = generate_token(&user, cfg)?;
  let refresh_token = issue_refresh_token(&txn, cfg, user.id).await?;

  txn.commit().await?;

  Ok(AuthResponse {
    token,
    refresh_token,
    user: UserDto::from(user),
  })
}

async fn create_user<C>(
  conn: &C,
  cfg: &Config,
  email: &str,
  name: Option<&str>,
) -> Result<UserEntities::Model, ApiError>
where
  C: sea_orm::ConnectionTrait,
{
  // The password column is required, so the user gets a random one nobody
  // knows: password login stays impossible until a reset sets a real one.
  let random: [u8; 32] = rand::rng().random();
  let password = hash(URL_SAFE_NO_PAD.encode(random), cfg.bcrypt_cost)
    .map_err(|e| ApiError::InternalError(anyhow!("Failed to hash password: {}", e)))?;

  let name = name
    .filter(|name| !name.is_empty())
    .unwrap_or_else(|| email.split('@').next().unwrap_or(email));

  Ok(
    UserEntities::ActiveModel {
      id: Set(Uuid::new_v4()),
      email: Set(email.to_string()),
      password: Set(password),
      name: Set(name.chars().take(100).collect()),
      // The provider already verified the email.
      status: Set(UserStatus::Active),
      ..Default::default()
    }
    .insert(conn)
    .await?,
  )
}
