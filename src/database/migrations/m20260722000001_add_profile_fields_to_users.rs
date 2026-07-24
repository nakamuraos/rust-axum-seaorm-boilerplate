use sea_orm_migration::prelude::*;

use crate::modules::users::entities::Entity as UserEntity;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Iden)]
enum Users {
  Phone,
  Bio,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
  async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    // `add_column_if_not_exists` keeps this idempotent alongside the entity-first
    // create migration: a no-op on fresh databases (the create already derived
    // these columns from the entity) and the actual add on pre-existing databases.
    manager
      .alter_table(
        Table::alter()
          .table(UserEntity)
          .add_column_if_not_exists(ColumnDef::new(Users::Phone).string().null())
          .to_owned(),
      )
      .await?;

    manager
      .alter_table(
        Table::alter()
          .table(UserEntity)
          .add_column_if_not_exists(ColumnDef::new(Users::Bio).text().null())
          .to_owned(),
      )
      .await
  }

  async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    manager
      .alter_table(
        Table::alter()
          .table(UserEntity)
          .drop_column(Users::Phone)
          .to_owned(),
      )
      .await?;

    manager
      .alter_table(
        Table::alter()
          .table(UserEntity)
          .drop_column(Users::Bio)
          .to_owned(),
      )
      .await
  }
}
