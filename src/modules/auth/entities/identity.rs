use chrono::{DateTime, Utc};
use sea_orm::{ActiveValue::Set, entity::prelude::*};
use serde::{Deserialize, Serialize};

/// An account of a user at an external identity provider.
///
/// `(provider, subject)` is unique: the subject is the provider's stable id for
/// the account, unlike the email, which can change or be recycled.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_identities")]
pub struct Model {
  #[sea_orm(primary_key, auto_increment = false)]
  pub id: Uuid,
  pub user_id: Uuid,
  pub provider: String,
  pub subject: String,
  #[sea_orm(
    column_type = "TimestampWithTimeZone",
    default_expr = "Expr::current_timestamp()"
  )]
  pub created_at: DateTime<Utc>,
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
