use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_status")]
pub enum UserStatus {
  #[sea_orm(string_value = "Active")]
  Active,
  #[sea_orm(string_value = "Inactive")]
  Inactive,
  #[sea_orm(string_value = "Banned")]
  Banned,
}

impl Default for UserStatus {
  fn default() -> Self {
    Self::Inactive
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_user_status_default() {
    assert_eq!(UserStatus::default(), UserStatus::Inactive);
  }

  #[test]
  fn test_user_status_variants() {
    assert_eq!(UserStatus::Active, UserStatus::Active);
    assert_eq!(UserStatus::Inactive, UserStatus::Inactive);
    assert_eq!(UserStatus::Banned, UserStatus::Banned);
    assert_ne!(UserStatus::Active, UserStatus::Inactive);
    assert_ne!(UserStatus::Active, UserStatus::Banned);
  }

  #[test]
  fn test_user_status_serialization() {
    let active = UserStatus::Active;
    let inactive = UserStatus::Inactive;
    let banned = UserStatus::Banned;

    let active_json = serde_json::to_string(&active).unwrap();
    let inactive_json = serde_json::to_string(&inactive).unwrap();
    let banned_json = serde_json::to_string(&banned).unwrap();

    assert_eq!(active_json, "\"Active\"");
    assert_eq!(inactive_json, "\"Inactive\"");
    assert_eq!(banned_json, "\"Banned\"");
  }

  #[test]
  fn test_user_status_deserialization() {
    let active_json = "\"Active\"";
    let inactive_json = "\"Inactive\"";
    let banned_json = "\"Banned\"";

    let active: UserStatus = serde_json::from_str(active_json).unwrap();
    let inactive: UserStatus = serde_json::from_str(inactive_json).unwrap();
    let banned: UserStatus = serde_json::from_str(banned_json).unwrap();

    assert_eq!(active, UserStatus::Active);
    assert_eq!(inactive, UserStatus::Inactive);
    assert_eq!(banned, UserStatus::Banned);
  }
}
