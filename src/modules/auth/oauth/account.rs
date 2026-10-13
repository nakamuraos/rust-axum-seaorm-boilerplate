use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
  TransactionTrait,
};
use uuid::Uuid;

use super::Profile;
use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::modules::auth::dto::AuthResponse;
use crate::modules::auth::entities::identity;
use crate::modules::auth::password;
use crate::modules::auth::service::open_session;
use crate::modules::auth::{accounts, dto::OwnershipProofResponse, ownership};
use crate::modules::users::entities::{self as UserEntities};
use crate::modules::users::enums::UserStatus;

/// Finds or creates the user behind a provider account and opens a session.
///
/// A known `(provider, subject)` identifies the account. New identities require
/// a verified email that is not already attached to a local account.
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
      .lock_exclusive()
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
        Some(_) => {
          return Err(ApiError::Unauthorized(
            "An account with this email already exists. Use its existing sign-in method"
              .to_string(),
          ));
        }
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

  let auth = open_session(&txn, cfg, user).await?;
  txn.commit().await?;
  Ok(auth)
}

pub(crate) async fn link_identity(
  conn: &DatabaseConnection,
  cfg: &Config,
  proof_token: &str,
  provider: &str,
  profile: Profile,
) -> Result<AuthResponse, ApiError> {
  let proof = ownership::verify(cfg, proof_token)?;
  let txn = conn.begin().await?;
  let user = accounts::locked_user(&txn, proof.user_id).await?;
  proof.check_user(&user)?;
  let linked = identity::Entity::find()
    .filter(identity::Column::Provider.eq(provider))
    .filter(identity::Column::Subject.eq(&profile.subject))
    .one(&txn)
    .await?;
  match linked {
    Some(linked) if linked.user_id != user.id => {
      return Err(ApiError::Conflict(
        "Identity belongs to another account. Authenticate both accounts to merge".into(),
      ));
    }
    Some(_) => {}
    None => {
      identity::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        provider: Set(provider.into()),
        subject: Set(profile.subject),
        ..Default::default()
      }
      .insert(&txn)
      .await
      .map_err(|error| match error.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => ApiError::Conflict(
          "Identity is already connected. Authenticate both accounts to merge".into(),
        ),
        _ => ApiError::from(error),
      })?;
    }
  }
  let auth = accounts::renewed_session(&txn, cfg, user).await?;
  txn.commit().await?;
  Ok(auth)
}

pub(crate) async fn verify_identity(
  conn: &DatabaseConnection,
  cfg: &Config,
  user_id: Uuid,
  session_version: i64,
  provider: &str,
  profile: Profile,
) -> Result<OwnershipProofResponse, ApiError> {
  let txn = conn.begin().await?;
  let user = accounts::locked_user(&txn, user_id).await?;
  if user.session_version != session_version {
    return Err(ApiError::Unauthorized("Session has been revoked".into()));
  }
  let linked = identity::Entity::find()
    .filter(identity::Column::Provider.eq(provider))
    .filter(identity::Column::Subject.eq(&profile.subject))
    .one(&txn)
    .await?;
  if linked.is_none_or(|identity| identity.user_id != user.id) {
    return Err(ApiError::Unauthorized(
      "Provider identity does not belong to this account".into(),
    ));
  }
  let proof = ownership::issue(cfg, &user)?;
  txn.commit().await?;
  Ok(proof)
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
  let password = password::hash(URL_SAFE_NO_PAD.encode(random), cfg.bcrypt_cost).await?;

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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::modules::auth::service::tests::{refresh_token, user};
  use crate::modules::users::enums::UserRole;
  use sea_orm::{DbBackend, MockDatabase};

  fn profile(verified: bool) -> Profile {
    Profile {
      subject: "provider-subject".into(),
      email: Some("victim@example.com".into()),
      email_verified: verified,
      name: None,
    }
  }

  #[tokio::test]
  async fn security_oauth_does_not_link_by_email() {
    let account = user(UserStatus::Active, UserRole::User);
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([Vec::<identity::Model>::new()])
      .append_query_results([[account]])
      .into_connection();
    let result = sign_in(&db, &config(), "github", profile(true)).await;
    assert!(matches!(result, Err(ApiError::Unauthorized(_))));
  }

  #[tokio::test]
  async fn security_oauth_rejects_unverified_email() {
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([Vec::<identity::Model>::new()])
      .into_connection();
    let result = sign_in(&db, &config(), "github", profile(false)).await;
    assert!(matches!(result, Err(ApiError::Unauthorized(_))));
  }

  #[tokio::test]
  async fn security_oauth_linked_identity_checks_status() {
    for status in [UserStatus::Active, UserStatus::Inactive, UserStatus::Banned] {
      let account = user(status.clone(), UserRole::User);
      let linked = identity::Model {
        id: Uuid::new_v4(),
        user_id: account.id,
        provider: "github".into(),
        subject: "provider-subject".into(),
        created_at: chrono::Utc::now(),
      };
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[linked]])
        .append_query_results([[account.clone()]])
        .append_query_results([[refresh_token(account.id)]])
        .into_connection();
      let result = sign_in(&db, &config(), "github", profile(true)).await;
      if status == UserStatus::Active {
        assert_eq!(result.unwrap().user.id, account.id.to_string());
      } else {
        assert!(matches!(result, Err(ApiError::Forbidden(_))));
      }
    }
  }
  #[tokio::test]
  async fn test_link_rejects_identity_owned_by_another_account() {
    let cfg = config();
    let target = user(UserStatus::Active, UserRole::User);
    let proof = ownership::issue(&cfg, &target).unwrap();
    let linked = identity::Model {
      id: Uuid::new_v4(),
      user_id: Uuid::new_v4(),
      provider: "github".into(),
      subject: "provider-subject".into(),
      created_at: chrono::Utc::now(),
    };
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[target]])
      .append_query_results([[linked]])
      .into_connection();
    assert!(matches!(
      link_identity(&db, &cfg, &proof.proof_token, "github", profile(true)).await,
      Err(ApiError::Conflict(_))
    ));
    assert!(!format!("{:?}", db.into_transaction_log()).contains("SET "));
  }

  #[tokio::test]
  async fn test_identity_verification_requires_matching_owner_and_session() {
    for scenario in 0..3 {
      let cfg = config();
      let target = user(UserStatus::Active, UserRole::User);
      let linked = identity::Model {
        id: Uuid::new_v4(),
        user_id: if scenario == 0 {
          Uuid::new_v4()
        } else {
          target.id
        },
        provider: "github".into(),
        subject: "provider-subject".into(),
        created_at: chrono::Utc::now(),
      };
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[target.clone()]])
        .append_query_results([[linked]])
        .into_connection();
      let result = verify_identity(
        &db,
        &cfg,
        target.id,
        if scenario == 1 { 1 } else { 0 },
        "github",
        profile(false),
      )
      .await;
      if scenario == 2 {
        ownership::verify(&cfg, &result.unwrap().proof_token)
          .unwrap()
          .check_user(&target)
          .unwrap();
      } else {
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
      }
    }
  }

  #[tokio::test]
  #[ignore = "requires SECURITY_TEST_DATABASE_URL pointing to an isolated PostgreSQL database"]
  async fn security_link_consumes_proof_and_reauthenticates_identity() {
    use crate::database::migrations::{Migrator, MigratorTrait};
    use crate::modules::auth::dto::{RefreshRequest, RegisterRequest};
    let db = sea_orm::Database::connect(
      std::env::var("SECURITY_TEST_DATABASE_URL").expect("SECURITY_TEST_DATABASE_URL"),
    )
    .await
    .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let cfg = config();
    let auth = crate::modules::auth::service::register(
      &db,
      &cfg,
      RegisterRequest {
        email: format!("link-{}@example.com", Uuid::new_v4()),
        password: "target-password".into(),
        name: "Link target".into(),
      },
    )
    .await
    .unwrap();
    let id = auth.user.id.parse::<Uuid>().unwrap();
    let proof = accounts::password_proof(&db, &cfg, id, "target-password".into())
      .await
      .unwrap();
    let subject = Uuid::new_v4().to_string();
    let profile = || Profile {
      subject: subject.clone(),
      email: None,
      email_verified: false,
      name: None,
    };
    let linked = link_identity(&db, &cfg, &proof.proof_token, "github", profile())
      .await
      .unwrap();
    assert_eq!(linked.user.id, auth.user.id);
    assert_eq!(accounts::identities(&db, id).await.unwrap().len(), 1);
    assert!(
      link_identity(&db, &cfg, &proof.proof_token, "github", profile())
        .await
        .is_err()
    );
    assert!(
      crate::modules::auth::service::refresh(
        &db,
        &cfg,
        RefreshRequest {
          refresh_token: auth.refresh_token
        }
      )
      .await
      .is_err()
    );
    let user = UserEntities::Entity::find_by_id(id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    let proof = verify_identity(&db, &cfg, id, user.session_version, "github", profile())
      .await
      .unwrap();
    ownership::verify(&cfg, &proof.proof_token)
      .unwrap()
      .check_user(&user)
      .unwrap();
    assert!(
      verify_identity(&db, &cfg, id, user.session_version - 1, "github", profile())
        .await
        .is_err()
    );
    assert_eq!(
      sign_in(&db, &cfg, "github", profile())
        .await
        .unwrap()
        .user
        .id,
      auth.user.id
    );
    UserEntities::Entity::delete_by_id(id)
      .exec(&db)
      .await
      .unwrap();
  }
}
