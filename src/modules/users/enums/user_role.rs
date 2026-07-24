use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_role")]
pub enum UserRole {
  #[sea_orm(string_value = "Admin")]
  Admin,
  #[sea_orm(string_value = "User")]
  User,
}

impl Default for UserRole {
  fn default() -> Self {
    Self::User
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_user_role_default() {
    assert_eq!(UserRole::default(), UserRole::User);
  }

  #[test]
  fn test_user_role_variants() {
    assert_eq!(UserRole::Admin, UserRole::Admin);
    assert_eq!(UserRole::User, UserRole::User);
    assert_ne!(UserRole::Admin, UserRole::User);
  }

  #[test]
  fn test_user_role_serialization() {
    let admin = UserRole::Admin;
    let user = UserRole::User;

    let admin_json = serde_json::to_string(&admin).unwrap();
    let user_json = serde_json::to_string(&user).unwrap();

    assert_eq!(admin_json, "\"Admin\"");
    assert_eq!(user_json, "\"User\"");
  }

  #[test]
  fn test_user_role_deserialization() {
    let admin_json = "\"Admin\"";
    let user_json = "\"User\"";

    let admin: UserRole = serde_json::from_str(admin_json).unwrap();
    let user: UserRole = serde_json::from_str(user_json).unwrap();

    assert_eq!(admin, UserRole::Admin);
    assert_eq!(user, UserRole::User);
  }
}
