use sea_orm::{ActiveEnum, DbBackend, Schema, Statement};
use sea_orm_migration::prelude::*;

use crate::modules::users::entities::Entity as UserEntity;
use crate::modules::users::enums::{UserRole, UserStatus};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
  async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    let schema = Schema::new(DbBackend::Postgres);

    // Check if enum type exists before creating it
    let db = manager.get_connection();
    let enum_name = UserStatus::name().to_string();
    let check_type = format!(
      "SELECT EXISTS (
        SELECT 1 FROM pg_type 
        WHERE typname = '{}'
      )",
      enum_name
    );
    let type_exists: bool = db
      .query_one_raw(Statement::from_string(DbBackend::Postgres, check_type))
      .await?
      .map(|row| row.try_get::<bool>("", "exists").unwrap_or(false))
      .unwrap_or(false);

    if !type_exists {
      // Create the enum type for Status
      manager
        .create_type(
          schema
            .create_enum_from_active_enum::<UserStatus>()
            .expect("UserStatus is a database enum"),
        )
        .await?;
    }

    // Check if enum type exists before creating it
    let db = manager.get_connection();
    let enum_name = UserRole::name().to_string();
    let check_type = format!(
      "SELECT EXISTS (
        SELECT 1 FROM pg_type 
        WHERE typname = '{}'
      )",
      enum_name
    );
    let type_exists: bool = db
      .query_one_raw(Statement::from_string(DbBackend::Postgres, check_type))
      .await?
      .map(|row| row.try_get::<bool>("", "exists").unwrap_or(false))
      .unwrap_or(false);

    if !type_exists {
      // Create the enum type for Role
      manager
        .create_type(
          schema
            .create_enum_from_active_enum::<UserRole>()
            .expect("UserRole is a database enum"),
        )
        .await?;
    }

    // Derive the users table straight from the entity definition, so the schema
    // has a single source of truth (columns, types and defaults live on the entity).
    manager
      .create_table(
        schema
          .create_table_from_entity(UserEntity)
          .if_not_exists()
          .to_owned(),
      )
      .await
  }

  async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    // Drop the users table first
    let result = manager
      .drop_table(Table::drop().table(UserEntity).to_owned())
      .await?;

    // Check and drop UserStatus enum if it exists
    let db = manager.get_connection();
    let enum_name = UserStatus::name().to_string();
    let check_type = format!(
      "SELECT EXISTS (
        SELECT 1 FROM pg_type 
        WHERE typname = '{}'
      )",
      enum_name
    );
    let type_exists: bool = db
      .query_one_raw(Statement::from_string(DbBackend::Postgres, check_type))
      .await?
      .map(|row| row.try_get::<bool>("", "exists").unwrap_or(false))
      .unwrap_or(false);

    if type_exists {
      let drop_type = format!("DROP TYPE IF EXISTS {}", enum_name);
      manager
        .get_connection()
        .execute_raw(Statement::from_string(DbBackend::Postgres, drop_type))
        .await?;
    }

    // Check and drop UserRole enum if it exists
    let enum_name = UserRole::name().to_string();
    let check_type = format!(
      "SELECT EXISTS (
        SELECT 1 FROM pg_type 
        WHERE typname = '{}'
      )",
      enum_name
    );
    let type_exists: bool = db
      .query_one_raw(Statement::from_string(DbBackend::Postgres, check_type))
      .await?
      .map(|row| row.try_get::<bool>("", "exists").unwrap_or(false))
      .unwrap_or(false);

    if type_exists {
      let drop_type = format!("DROP TYPE IF EXISTS {}", enum_name);
      manager
        .get_connection()
        .execute_raw(Statement::from_string(DbBackend::Postgres, drop_type))
        .await?;
    }

    Ok(result)
  }
}
