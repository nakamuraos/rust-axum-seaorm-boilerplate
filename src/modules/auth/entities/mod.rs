use chrono::{DateTime, Utc};
use sea_orm::{ActiveValue::Set, entity::prelude::*};
use serde::{Deserialize, Serialize};

/// A refresh token issued to a user.
///
/// Only the hash of the token is stored, so a database leak does not hand out
/// usable tokens. A row is kept after revocation to make reuse of a rotated
/// token detectable.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
  #[sea_orm(primary_key, auto_increment = false)]
  pub id: Uuid,
  pub user_id: Uuid,
  #[sea_orm(unique)]
  pub token_hash: String,
  #[sea_orm(column_type = "TimestampWithTimeZone")]
  pub expires_at: DateTime<Utc>,
  #[sea_orm(column_type = "TimestampWithTimeZone", nullable)]
  pub revoked_at: Option<DateTime<Utc>>,
  #[sea_orm(
    column_type = "TimestampWithTimeZone",
    default_expr = "Expr::current_timestamp()"
  )]
  pub created_at: DateTime<Utc>,
}

impl Model {
  /// Whether the token can still be exchanged for a new pair.
  pub fn is_usable(&self) -> bool {
    self.revoked_at.is_none() && self.expires_at > Utc::now()
  }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
  #[sea_orm(
    belongs_to = "crate::modules::users::entities::Entity",
    from = "Column::UserId",
    to = "crate::modules::users::entities::Column::Id",
    on_delete = "Cascade"
  )]
  User,
}

impl Related<crate::modules::users::entities::Entity> for Entity {
  fn to() -> RelationDef {
    Relation::User.def()
  }
}

impl ActiveModelBehavior for ActiveModel {
  fn new() -> Self {
    Self {
      id: Set(Uuid::new_v4()),
      ..ActiveModelTrait::default()
    }
  }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelatedEntity)]
pub enum RelatedEntity {
  #[sea_orm(entity = "crate::modules::users::entities::Entity")]
  User,
}
