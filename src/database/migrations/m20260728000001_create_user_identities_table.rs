use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;

use crate::modules::auth::entities::identity::{
  Column as IdentityColumn, Entity as IdentityEntity,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
  async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    let schema = Schema::new(DbBackend::Postgres);

    manager
      .create_table(
        schema
          .create_table_from_entity(IdentityEntity)
          .if_not_exists()
          .to_owned(),
      )
      .await?;

    // One provider account maps to exactly one user.
    manager
      .create_index(
        Index::create()
          .if_not_exists()
          .name("idx_user_identities_provider_subject")
          .table(IdentityEntity)
          .col(IdentityColumn::Provider)
          .col(IdentityColumn::Subject)
          .unique()
          .to_owned(),
      )
      .await?;

    manager
      .create_index(
        Index::create()
          .if_not_exists()
          .name("idx_user_identities_user_id")
          .table(IdentityEntity)
          .col(IdentityColumn::UserId)
          .to_owned(),
      )
      .await
  }

  async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    manager
      .drop_table(Table::drop().table(IdentityEntity).to_owned())
      .await
  }
}
