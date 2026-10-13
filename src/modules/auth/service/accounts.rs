use chrono::Utc;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter,
  QueryOrder, QuerySelect, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::common::{config::Config, errors::ApiError};
use crate::modules::auth::{
  dto::{
    AuthResponse, LinkedIdentityDto, MergeAccountsRequest, MergePreviewResponse,
    OwnershipProofResponse,
  },
  entities::{self as tokens, identity},
  service::{self, ownership, password},
};
use crate::modules::users::{entities as users, enums::UserStatus};

pub(crate) async fn password_proof(
  conn: &DatabaseConnection,
  cfg: &Config,
  user_id: Uuid,
  password: String,
) -> Result<OwnershipProofResponse, ApiError> {
  let user = users::Entity::find_by_id(user_id)
    .one(conn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".into()))?;
  service::ensure_active(&user.status)?;
  if !password::verify(password, user.password.clone()).await? {
    return Err(ApiError::Unauthorized("Invalid credentials".into()));
  }
  ownership::issue(cfg, &user)
}

pub(crate) async fn identities(
  conn: &DatabaseConnection,
  user_id: Uuid,
) -> Result<Vec<LinkedIdentityDto>, ApiError> {
  Ok(
    identity::Entity::find()
      .filter(identity::Column::UserId.eq(user_id))
      .order_by_asc(identity::Column::CreatedAt)
      .all(conn)
      .await?
      .into_iter()
      .map(LinkedIdentityDto::from)
      .collect(),
  )
}

pub(crate) async fn preview(
  conn: &DatabaseConnection,
  cfg: &Config,
  target_id: Uuid,
  req: &MergeAccountsRequest,
) -> Result<MergePreviewResponse, ApiError> {
  let txn = conn.begin().await?;
  let (target, source) = verified_accounts(&txn, cfg, target_id, req).await?;
  let identities_to_transfer = identity::Entity::find()
    .filter(identity::Column::UserId.eq(source.id))
    .all(&txn)
    .await?
    .into_iter()
    .map(LinkedIdentityDto::from)
    .collect();
  let conflicts = merge_conflicts(&target, &source);
  let response = MergePreviewResponse {
    target: target.into(),
    source: source.into(),
    identities_to_transfer,
    can_merge: conflicts.is_empty(),
    conflicts,
    consequences: vec![
      "The target ID, email, password, profile and role remain unchanged".into(),
      "All source OAuth identities move to the target account".into(),
      "The source profile is retained for auditing and its password login is disabled".into(),
      "All existing sessions and account proofs of both accounts are revoked".into(),
      "Application data, organizations, subscriptions and billing are not merged automatically"
        .into(),
    ],
  };
  txn.commit().await?;
  Ok(response)
}

pub(crate) async fn merge(
  conn: &DatabaseConnection,
  cfg: &Config,
  target_id: Uuid,
  req: MergeAccountsRequest,
) -> Result<AuthResponse, ApiError> {
  if !req.confirm {
    return Err(ApiError::InvalidRequest(
      "Explicit merge confirmation is required".into(),
    ));
  }
  let txn = conn.begin().await?;
  let (target, source) = verified_accounts(&txn, cfg, target_id, &req).await?;
  if !merge_conflicts(&target, &source).is_empty() {
    return Err(ApiError::Forbidden(
      "Accounts with different roles cannot be merged".into(),
    ));
  }

  identity::Entity::update_many()
    .col_expr(
      identity::Column::UserId,
      sea_orm::sea_query::Expr::value(target.id),
    )
    .filter(identity::Column::UserId.eq(source.id))
    .exec(&txn)
    .await?;

  let source_id = source.id;
  let next_version = increment_version(source.session_version)?;
  let mut merged: users::ActiveModel = source.into();
  merged.status = Set(UserStatus::Merged);
  merged.merged_into = Set(Some(target.id));
  merged.merged_at = Set(Some(Utc::now()));
  merged.session_version = Set(next_version);
  merged.update(&txn).await?;
  revoke_refresh_tokens(&txn, source_id).await?;

  let auth = renewed_session(&txn, cfg, target).await?;
  txn.commit().await?;
  Ok(auth)
}

async fn verified_accounts(
  txn: &DatabaseTransaction,
  cfg: &Config,
  target_id: Uuid,
  req: &MergeAccountsRequest,
) -> Result<(users::Model, users::Model), ApiError> {
  if target_id == req.source_user_id {
    return Err(ApiError::InvalidRequest(
      "An account cannot be merged into itself".into(),
    ));
  }
  let target_proof = ownership::verify(cfg, &req.target_proof)?;
  let source_proof = ownership::verify(cfg, &req.source_proof)?;
  if target_proof.user_id != target_id || source_proof.user_id != req.source_user_id {
    return Err(ApiError::Unauthorized(
      "Account proofs do not match the requested merge".into(),
    ));
  }

  // A consistent lock order prevents opposing account operations from deadlocking.
  let accounts = users::Entity::find()
    .filter(users::Column::Id.is_in([target_id, req.source_user_id]))
    .order_by_asc(users::Column::Id)
    .lock_exclusive()
    .all(txn)
    .await?;
  let target = accounts
    .iter()
    .find(|user| user.id == target_id)
    .cloned()
    .ok_or_else(|| ApiError::Unauthorized("Target account no longer exists".into()))?;
  let source = accounts
    .into_iter()
    .find(|user| user.id == req.source_user_id)
    .ok_or_else(|| ApiError::Unauthorized("Source account no longer exists".into()))?;
  target_proof.check_user(&target)?;
  source_proof.check_user(&source)?;
  Ok((target, source))
}

fn merge_conflicts(target: &users::Model, source: &users::Model) -> Vec<String> {
  if target.role != source.role {
    vec!["Accounts have different roles; privileges cannot be merged automatically".into()]
  } else {
    Vec::new()
  }
}

#[cfg(feature = "oauth2")]
pub(crate) async fn locked_user(
  txn: &DatabaseTransaction,
  id: Uuid,
) -> Result<users::Model, ApiError> {
  let user = users::Entity::find_by_id(id)
    .lock_exclusive()
    .one(txn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".into()))?;
  service::ensure_active(&user.status)?;
  Ok(user)
}

pub(crate) async fn renewed_session(
  txn: &DatabaseTransaction,
  cfg: &Config,
  user: users::Model,
) -> Result<AuthResponse, ApiError> {
  let next_version = increment_version(user.session_version)?;
  let mut active: users::ActiveModel = user.into();
  active.session_version = Set(next_version);
  let user = active.update(txn).await?;
  revoke_refresh_tokens(txn, user.id).await?;
  service::open_session(txn, cfg, user).await
}

fn increment_version(version: i64) -> Result<i64, ApiError> {
  version
    .checked_add(1)
    .ok_or_else(|| ApiError::InternalError(anyhow::anyhow!("Session version exhausted")))
}

async fn revoke_refresh_tokens(txn: &DatabaseTransaction, user_id: Uuid) -> Result<(), ApiError> {
  tokens::Entity::update_many()
    .col_expr(
      tokens::Column::RevokedAt,
      sea_orm::sea_query::Expr::value(Utc::now()),
    )
    .filter(tokens::Column::UserId.eq(user_id))
    .filter(tokens::Column::RevokedAt.is_null())
    .exec(txn)
    .await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::modules::auth::service::tests::user;
  use crate::modules::users::enums::UserRole;
  use sea_orm::{DbBackend, MockDatabase};

  fn request(cfg: &Config, target: &users::Model, source: &users::Model) -> MergeAccountsRequest {
    MergeAccountsRequest {
      source_user_id: source.id,
      target_proof: ownership::issue(cfg, target).unwrap().proof_token,
      source_proof: ownership::issue(cfg, source).unwrap().proof_token,
      confirm: true,
    }
  }

  #[tokio::test]
  async fn test_merge_requires_confirmation_and_distinct_accounts() {
    let cfg = config();
    let target = user(UserStatus::Active, UserRole::User);
    let source = user(UserStatus::Active, UserRole::User);
    let db = MockDatabase::new(DbBackend::Postgres).into_connection();
    let mut req = request(&cfg, &target, &source);
    req.confirm = false;
    assert!(matches!(
      merge(&db, &cfg, target.id, req).await,
      Err(ApiError::InvalidRequest(_))
    ));
    let req = request(&cfg, &target, &target);
    assert!(matches!(
      merge(&db, &cfg, target.id, req).await,
      Err(ApiError::InvalidRequest(_))
    ));
  }

  #[tokio::test]
  async fn test_merge_rejects_swapped_missing_and_stale_proofs() {
    for scenario in 0..3 {
      let cfg = config();
      let target = user(UserStatus::Active, UserRole::User);
      let mut source = user(UserStatus::Active, UserRole::User);
      let mut req = request(&cfg, &target, &source);
      match scenario {
        0 => std::mem::swap(&mut req.target_proof, &mut req.source_proof),
        1 => req.source_proof.clear(),
        _ => source.session_version += 1,
      }
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[target.clone(), source]])
        .into_connection();
      assert!(matches!(
        merge(&db, &cfg, target.id, req).await,
        Err(ApiError::Unauthorized(_))
      ));
    }
  }

  #[tokio::test]
  async fn test_preview_reports_role_conflicts_without_mutation() {
    let cfg = config();
    let target = user(UserStatus::Active, UserRole::User);
    let source = user(UserStatus::Active, UserRole::Admin);
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[target.clone(), source.clone()]])
      .append_query_results([Vec::<identity::Model>::new()])
      .into_connection();
    let response = preview(&db, &cfg, target.id, &request(&cfg, &target, &source))
      .await
      .unwrap();
    assert!(!response.can_merge);
    assert_eq!(response.conflicts.len(), 1);
    assert_eq!(response.target.id, target.id.to_string());
    let statements = format!("{:?}", db.into_transaction_log());
    assert!(!statements.contains("SET "));
    assert!(statements.contains("FOR UPDATE"));

    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[target.clone(), source.clone()]])
      .into_connection();
    assert!(matches!(
      merge(&db, &cfg, target.id, request(&cfg, &target, &source)).await,
      Err(ApiError::Forbidden(_))
    ));
    assert!(!format!("{:?}", db.into_transaction_log()).contains("SET "));
  }

  #[tokio::test]
  async fn test_password_proof_requires_current_credentials_and_active_status() {
    for status in [UserStatus::Active, UserStatus::Banned, UserStatus::Merged] {
      let mut account = user(status.clone(), UserRole::User);
      account.password = bcrypt::hash("correct-password", 4).unwrap();
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_query_results([[account.clone()]])
        .into_connection();
      let result = password_proof(&db, &config(), account.id, "wrong-password".into()).await;
      if status == UserStatus::Active {
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
      } else {
        assert!(matches!(result, Err(ApiError::Forbidden(_))));
      }
    }
    let mut account = user(UserStatus::Active, UserRole::User);
    account.password = bcrypt::hash("correct-password", 4).unwrap();
    let db = MockDatabase::new(DbBackend::Postgres)
      .append_query_results([[account.clone()]])
      .into_connection();
    let proof = password_proof(&db, &config(), account.id, "correct-password".into())
      .await
      .unwrap();
    ownership::verify(&config(), &proof.proof_token)
      .unwrap()
      .check_user(&account)
      .unwrap();
  }

  #[tokio::test]
  #[ignore = "requires SECURITY_TEST_DATABASE_URL pointing to an isolated PostgreSQL database"]
  async fn security_merge_preserves_primary_and_revokes_sessions() {
    use crate::database::migrations::{Migrator, MigratorTrait};
    use crate::modules::auth::dto::{LoginRequest, RefreshRequest, RegisterRequest};
    use sea_orm::Database;
    let db = Database::connect(
      std::env::var("SECURITY_TEST_DATABASE_URL").expect("SECURITY_TEST_DATABASE_URL"),
    )
    .await
    .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let cfg = config();
    let target_auth = service::register(
      &db,
      &cfg,
      RegisterRequest {
        email: format!("target-{}@example.com", Uuid::new_v4()),
        password: "target-password".into(),
        name: "Primary profile".into(),
      },
    )
    .await
    .unwrap();
    let source_auth = service::register(
      &db,
      &cfg,
      RegisterRequest {
        email: format!("source-{}@example.com", Uuid::new_v4()),
        password: "source-password".into(),
        name: "Secondary profile".into(),
      },
    )
    .await
    .unwrap();
    let target_id = target_auth.user.id.parse::<Uuid>().unwrap();
    let source_id = source_auth.user.id.parse::<Uuid>().unwrap();
    let target = users::Entity::find_by_id(target_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    let source = users::Entity::find_by_id(source_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    let subject = Uuid::new_v4().to_string();
    identity::ActiveModel {
      user_id: Set(source_id),
      provider: Set("github".into()),
      subject: Set(subject.clone()),
      ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    identity::ActiveModel {
      user_id: Set(source_id),
      provider: Set("oidc".into()),
      subject: Set(Uuid::new_v4().to_string()),
      ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let target_proof = password_proof(&db, &cfg, target_id, "target-password".into())
      .await
      .unwrap();
    #[cfg(feature = "oauth2")]
    let source_proof = crate::modules::auth::oauth::account::verify_identity(
      &db,
      &cfg,
      source_id,
      source.session_version,
      "github",
      crate::modules::auth::oauth::Profile {
        subject: subject.clone(),
        email: None,
        email_verified: false,
        name: None,
      },
    )
    .await
    .unwrap();
    #[cfg(not(feature = "oauth2"))]
    let source_proof = password_proof(&db, &cfg, source_id, "source-password".into())
      .await
      .unwrap();
    let mut req = MergeAccountsRequest {
      source_user_id: source_id,
      target_proof: target_proof.proof_token,
      source_proof: source_proof.proof_token,
      confirm: false,
    };
    let before = preview(&db, &cfg, target_id, &req).await.unwrap();
    assert!(before.can_merge);
    assert_eq!(before.identities_to_transfer.len(), 2);
    assert_eq!(
      users::Entity::find_by_id(source_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap(),
      source
    );
    req.confirm = true;
    let replay = request(&cfg, &target, &source);
    let merged_auth = merge(&db, &cfg, target_id, req).await.unwrap();
    assert_eq!(merged_auth.user.id, target_id.to_string());
    {
      use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
      };
      use tower::ServiceExt;
      let state = crate::app::AppState {
        db: crate::database::Db { conn: db.clone() },
        cfg: cfg.clone(),
      };
      let app = Router::new()
        .route("/me", get(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(
          state,
          crate::modules::auth::guards::auth_guard,
        ));
      for (token, expected) in [
        (&target_auth.token, StatusCode::UNAUTHORIZED),
        (&source_auth.token, StatusCode::FORBIDDEN),
        (&merged_auth.token, StatusCode::OK),
      ] {
        let response = app
          .clone()
          .oneshot(
            Request::builder()
              .uri("/me")
              .header("authorization", format!("Bearer {token}"))
              .body(Body::empty())
              .unwrap(),
          )
          .await
          .unwrap();
        assert_eq!(response.status(), expected);
      }
    }

    let primary = users::Entity::find_by_id(target_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(primary.password, target.password);
    assert_eq!(primary.email, target.email);
    assert_eq!(primary.name, target.name);
    assert_eq!(primary.role, target.role);
    assert_eq!(primary.session_version, target.session_version + 1);
    let secondary = users::Entity::find_by_id(source_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(secondary.status, UserStatus::Merged);
    assert_eq!(secondary.merged_into, Some(target_id));
    assert!(secondary.merged_at.is_some());
    assert_eq!(identities(&db, source_id).await.unwrap().len(), 0);
    assert_eq!(identities(&db, target_id).await.unwrap().len(), 2);
    assert!(merge(&db, &cfg, target_id, replay).await.is_err());
    for old in [&target_auth.refresh_token, &source_auth.refresh_token] {
      assert!(
        service::refresh(
          &db,
          &cfg,
          RefreshRequest {
            refresh_token: old.clone()
          }
        )
        .await
        .is_err()
      );
    }
    assert!(
      service::refresh(
        &db,
        &cfg,
        RefreshRequest {
          refresh_token: merged_auth.refresh_token
        }
      )
      .await
      .is_ok()
    );
    assert!(
      service::login(
        &db,
        &cfg,
        LoginRequest {
          email: source.email,
          password: "source-password".into()
        }
      )
      .await
      .is_err()
    );
    assert_eq!(
      service::login(
        &db,
        &cfg,
        LoginRequest {
          email: target.email,
          password: "target-password".into()
        }
      )
      .await
      .unwrap()
      .user
      .id,
      target_id.to_string()
    );
    #[cfg(feature = "oauth2")]
    {
      let auth = crate::modules::auth::oauth::account::sign_in(
        &db,
        &cfg,
        "github",
        crate::modules::auth::oauth::Profile {
          subject,
          email: None,
          email_verified: false,
          name: None,
        },
      )
      .await
      .unwrap();
      assert_eq!(auth.user.id, target_id.to_string());
    }
    users::Entity::delete_by_id(source_id)
      .exec(&db)
      .await
      .unwrap();
    users::Entity::delete_by_id(target_id)
      .exec(&db)
      .await
      .unwrap();
  }
  #[tokio::test]
  #[ignore = "requires SECURITY_TEST_DATABASE_URL pointing to an isolated PostgreSQL database"]
  async fn security_merge_is_atomic_and_only_one_request_wins() {
    use crate::database::migrations::{Migrator, MigratorTrait};
    use crate::modules::auth::dto::{RefreshRequest, RegisterRequest};
    let db = sea_orm::Database::connect(
      std::env::var("SECURITY_TEST_DATABASE_URL").expect("SECURITY_TEST_DATABASE_URL"),
    )
    .await
    .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let cfg = config();
    let mut registered = Vec::new();
    for label in ["atomic-target", "atomic-source"] {
      registered.push(
        service::register(
          &db,
          &cfg,
          RegisterRequest {
            email: format!("{label}-{}@example.com", Uuid::new_v4()),
            password: "test-password".into(),
            name: label.into(),
          },
        )
        .await
        .unwrap(),
      );
    }
    let target_id = registered[0].user.id.parse::<Uuid>().unwrap();
    let source_id = registered[1].user.id.parse::<Uuid>().unwrap();
    let target = users::Entity::find_by_id(target_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    let source = users::Entity::find_by_id(source_id)
      .one(&db)
      .await
      .unwrap()
      .unwrap();
    let linked = identity::ActiveModel {
      user_id: Set(source_id),
      provider: Set("github".into()),
      subject: Set(Uuid::new_v4().to_string()),
      ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let mut exhausted: users::ActiveModel = source.clone().into();
    exhausted.session_version = Set(i64::MAX);
    let exhausted = exhausted.update(&db).await.unwrap();
    assert!(matches!(
      merge(&db, &cfg, target_id, request(&cfg, &target, &exhausted)).await,
      Err(ApiError::InternalError(_))
    ));
    assert_eq!(
      identity::Entity::find_by_id(linked.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .user_id,
      source_id
    );
    assert_eq!(
      users::Entity::find_by_id(target_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap(),
      target
    );
    assert_eq!(
      users::Entity::find_by_id(source_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap(),
      exhausted
    );
    let mut active: users::ActiveModel = exhausted.into();
    active.session_version = Set(0);
    active.update(&db).await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8 {
      let (keep, remove) = if index % 2 == 0 {
        (&target, &source)
      } else {
        (&source, &target)
      };
      let keep_id = keep.id;
      let (db, cfg, barrier, req) = (
        db.clone(),
        cfg.clone(),
        barrier.clone(),
        request(&cfg, keep, remove),
      );
      tasks.spawn(async move {
        barrier.wait().await;
        merge(&db, &cfg, keep_id, req).await
      });
    }
    let mut refreshes = tokio::task::JoinSet::new();
    for index in 0..8 {
      let (db, cfg, barrier, secret) = (
        db.clone(),
        cfg.clone(),
        barrier.clone(),
        registered[index % 2].refresh_token.clone(),
      );
      refreshes.spawn(async move {
        barrier.wait().await;
        service::refresh(
          &db,
          &cfg,
          RefreshRequest {
            refresh_token: secret,
          },
        )
        .await
      });
    }
    let mut winners = Vec::new();
    while let Some(result) = tasks.join_next().await {
      match result.unwrap() {
        Ok(auth) => winners.push(auth),
        Err(ApiError::Unauthorized(_) | ApiError::Forbidden(_)) => {}
        Err(error) => panic!("Unexpected merge failure: {error}"),
      }
    }
    assert_eq!(winners.len(), 1);
    while let Some(result) = refreshes.join_next().await {
      match result.unwrap() {
        Ok(pair) => assert!(
          service::refresh(
            &db,
            &cfg,
            RefreshRequest {
              refresh_token: pair.refresh_token
            }
          )
          .await
          .is_err()
        ),
        Err(ApiError::Unauthorized(_) | ApiError::Forbidden(_)) => {}
        Err(error) => panic!("Unexpected concurrent refresh failure: {error}"),
      }
    }

    assert_eq!(
      identity::Entity::find_by_id(linked.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .user_id
        .to_string(),
      winners[0].user.id
    );
    for auth in registered {
      assert!(
        service::refresh(
          &db,
          &cfg,
          RefreshRequest {
            refresh_token: auth.refresh_token
          }
        )
        .await
        .is_err()
      );
    }
    assert!(
      service::refresh(
        &db,
        &cfg,
        RefreshRequest {
          refresh_token: winners.pop().unwrap().refresh_token
        }
      )
      .await
      .is_ok()
    );
    users::Entity::delete_by_id(source_id)
      .exec(&db)
      .await
      .unwrap();
    users::Entity::delete_by_id(target_id)
      .exec(&db)
      .await
      .unwrap();
  }
}
