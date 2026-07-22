use chrono::{DateTime, Utc};
use sea_orm::{ActiveValue::Set, entity::prelude::*};
use serde::{Deserialize, Serialize};

use crate::modules::users::enums::{UserRole, UserStatus};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
  #[sea_orm(primary_key, auto_increment = false)]
  pub id: Uuid,
  pub email: String,
  pub name: String,
  pub password: String,
  pub phone: Option<String>,
  #[sea_orm(column_type = "Text", nullable)]
  pub bio: Option<String>,
  #[sea_orm(default_value = "Inactive")]
  pub status: UserStatus,
  #[sea_orm(default_value = "User")]
  pub role: UserRole,
  #[sea_orm(
    column_type = "TimestampWithTimeZone",
    default_expr = "Expr::current_timestamp()"
  )]
  pub created_at: DateTime<Utc>,
  #[sea_orm(
    column_type = "TimestampWithTimeZone",
    default_expr = "Expr::current_timestamp()"
  )]
  pub updated_at: DateTime<Utc>,
}

/// Read projection of a user that excludes the password hash, so list and detail
/// queries never load the sensitive column from the database.
#[derive(Clone, Debug, PartialEq, DerivePartialModel)]
#[sea_orm(entity = "Entity")]
pub struct UserProfile {
  pub id: Uuid,
  pub email: String,
  pub name: String,
  pub phone: Option<String>,
  pub bio: Option<String>,
  pub status: UserStatus,
  pub role: UserRole,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
  fn new() -> Self {
    Self {
      id: Set(Uuid::new_v4()),
      status: Set(UserStatus::Inactive),
      role: Set(UserRole::User),
      ..ActiveModelTrait::default()
    }
  }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelatedEntity)]
pub enum RelatedEntity {}
