mod users;

use sea_orm::DatabaseConnection;

use crate::common::config::Config;

pub async fn run(db: &DatabaseConnection, cfg: &Config) -> Result<(), sea_orm::DbErr> {
  users::seed(db, cfg).await?;
  Ok(())
}
