use sea_orm::{DbBackend, Statement};
use sea_orm_migration::prelude::*;

use crate::modules::users::entities::{Column, Entity};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
  async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    manager
      .get_connection()
      .execute_raw(Statement::from_string(
        DbBackend::Postgres,
        "ALTER TYPE user_status ADD VALUE IF NOT EXISTS 'Merged'",
      ))
      .await?;
    manager
      .alter_table(
        Table::alter()
          .table(Entity)
          .add_column_if_not_exists(
            ColumnDef::new(Column::SessionVersion)
              .big_integer()
              .not_null()
              .default(0),
          )
          .add_column_if_not_exists(ColumnDef::new(Column::MergedInto).uuid().null())
          .add_column_if_not_exists(
            ColumnDef::new(Column::MergedAt)
              .timestamp_with_time_zone()
              .null(),
          )
          .to_owned(),
      )
      .await
  }

  async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
    let manager = manager.begin().await?;
    manager
      .get_connection()
      .execute_raw(Statement::from_string(
        DbBackend::Postgres,
        "LOCK TABLE users IN ACCESS EXCLUSIVE MODE",
      ))
      .await?;
    let has_history = manager.get_connection().query_one_raw(Statement::from_string(
      DbBackend::Postgres,
      "SELECT EXISTS (SELECT 1 FROM users WHERE session_version <> 0 OR merged_into IS NOT NULL OR merged_at IS NOT NULL OR status::text = 'Merged') AS has_history",
    )).await?.ok_or_else(|| DbErr::Migration("Unable to verify account history".into()))?
      .try_get::<bool>("", "has_history")?;
    if has_history {
      return Err(DbErr::Migration(
        "Cannot remove account fields while merge history or revoked sessions exist".into(),
      ));
    }
    manager
      .alter_table(
        Table::alter()
          .table(Entity)
          .drop_column(Column::SessionVersion)
          .drop_column(Column::MergedInto)
          .drop_column(Column::MergedAt)
          .to_owned(),
      )
      .await?;
    manager.commit().await
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use sea_orm::{MockDatabase, MockExecResult, Value};
  use std::collections::BTreeMap;

  #[tokio::test]
  async fn test_rollback_preserves_merge_and_session_history() {
    for has_history in [false, true] {
      let db = MockDatabase::new(DbBackend::Postgres)
        .append_exec_results((0..2).map(|_| MockExecResult {
          last_insert_id: 0,
          rows_affected: 0,
        }))
        .append_query_results([[BTreeMap::from([(
          "has_history",
          Value::Bool(Some(has_history)),
        )])]])
        .into_connection();
      let result = Migration.down(&SchemaManager::new(&db)).await;
      assert_eq!(result.is_err(), has_history);
      let log = format!("{:?}", db.into_transaction_log());
      assert_eq!(log.contains("DROP COLUMN"), !has_history);
      assert!(log.contains("ACCESS EXCLUSIVE"));
    }
  }
}
