use bcrypt::hash;
use sea_orm::{ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tracing::info;
use uuid::Uuid;

use crate::common::config::Config;
use crate::modules::users::entities::{self, Column};
use crate::modules::users::enums::{UserRole, UserStatus};

struct SeedUser {
  email: &'static str,
  password: &'static str,
  name: &'static str,
  role: UserRole,
}

const SEED_USERS: &[SeedUser] = &[
  SeedUser {
    email: "admin@example.com",
    password: "Admin@123",
    name: "Admin",
    role: UserRole::Admin,
  },
  SeedUser {
    email: "user1@example.com",
    password: "User@1234",
    name: "User One",
    role: UserRole::User,
  },
  SeedUser {
    email: "user2@example.com",
    password: "User@1234",
    name: "User Two",
    role: UserRole::User,
  },
];

pub async fn seed(db: &DatabaseConnection, cfg: &Config) -> Result<(), sea_orm::DbErr> {
  for seed_user in SEED_USERS {
    let exists = entities::Entity::find()
      .filter(Column::Email.eq(seed_user.email))
      .one(db)
      .await?;

    if exists.is_some() {
      info!("Seed user '{}' already exists, skipping", seed_user.email);
      continue;
    }

    let password_hash = hash(seed_user.password.as_bytes(), cfg.bcrypt_cost)
      .map_err(|e| sea_orm::DbErr::Custom(format!("Failed to hash password: {}", e)))?;

    let user = entities::ActiveModel {
      id: Set(Uuid::new_v4()),
      email: Set(seed_user.email.to_string()),
      password: Set(password_hash),
      name: Set(seed_user.name.to_string()),
      status: Set(UserStatus::Active),
      role: Set(seed_user.role.clone()),
      ..Default::default()
    };

    entities::Entity::insert(user).exec(db).await?;
    info!("Seed user '{}' created successfully", seed_user.email);
  }

  Ok(())
}
