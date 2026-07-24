use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;

use crate::modules::auth::entities::{Column as RefreshTokenColumn, Entity as RefreshTokenEntity};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
  async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    let schema = Schema::new(DbBackend::Postgres);

    manager
      .create_table(
        schema
          .create_table_from_entity(RefreshTokenEntity)
          .if_not_exists()
          .to_owned(),
      )
      .await?;

    // Revoking every token of a user is a routine operation, so the user column
    // is indexed on its own.
    manager
      .create_index(
        Index::create()
          .if_not_exists()
          .name("idx_refresh_tokens_user_id")
          .table(RefreshTokenEntity)
          .col(RefreshTokenColumn::UserId)
          .to_owned(),
      )
      .await
  }

  async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    manager
      .drop_table(Table::drop().table(RefreshTokenEntity).to_owned())
      .await
  }
}
