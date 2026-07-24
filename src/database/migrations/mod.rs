pub use sea_orm_migration::prelude::*;

mod m20240126114845_create_users_table;
mod m20260722000001_add_profile_fields_to_users;
mod m20260724000001_create_refresh_tokens_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
  fn migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![
      Box::new(m20240126114845_create_users_table::Migration),
      Box::new(m20260722000001_add_profile_fields_to_users::Migration),
      Box::new(m20260724000001_create_refresh_tokens_table::Migration),
    ]
  }
}
