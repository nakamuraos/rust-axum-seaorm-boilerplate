use chrono::SecondsFormat;
use sea_orm::ActiveEnum;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::modules::users::entities::Model;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct UserCreate {
  #[validate(email(message = "invalid email format"))]
  pub email: String,
  #[validate(length(min = 8, max = 64, message = "must be between 8 and 64 characters"))]
  pub password: String,
  #[validate(length(min = 1, max = 100, message = "must be between 1 and 100 characters"))]
  pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct UserUpdate {
  #[validate(length(min = 1, max = 100, message = "must be between 1 and 100 characters"))]
  pub name: String,
}

// Custom type for OpenAPI documentation
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserDto {
  pub id: String,
  pub email: String,
  pub name: String,
  pub status: String,
  pub role: String,
  #[schema(format = "date-time")]
  pub created_at: Option<String>,
  #[schema(format = "date-time")]
  pub updated_at: Option<String>,
}

impl From<Model> for UserDto {
  fn from(model: Model) -> Self {
    Self {
      id: model.id.to_string(),
      email: model.email,
      name: model.name,
      status: model.status.into_value(),
      role: model.role.into_value(),
      created_at: model
        .created_at
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Millis, true)),
      updated_at: model
        .updated_at
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Millis, true)),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use validator::Validate;

  // --- UserCreate validation tests ---

  #[test]
  fn test_user_create_valid() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "Test User".to_string(),
    };
    assert!(user.validate().is_ok());
  }

  #[test]
  fn test_user_create_invalid_email() {
    let user = UserCreate {
      email: "not-an-email".to_string(),
      password: "password123".to_string(),
      name: "Test User".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
  }

  #[test]
  fn test_user_create_empty_email() {
    let user = UserCreate {
      email: "".to_string(),
      password: "password123".to_string(),
      name: "Test User".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
  }

  #[test]
  fn test_user_create_password_too_short() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "short".to_string(),
      name: "Test User".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("password"));
  }

  #[test]
  fn test_user_create_password_too_long() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "a".repeat(65),
      name: "Test User".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("password"));
  }

  #[test]
  fn test_user_create_name_empty() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("name"));
  }

  #[test]
  fn test_user_create_name_too_long() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "a".repeat(101),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("name"));
  }

  #[test]
  fn test_user_create_all_fields_invalid() {
    let user = UserCreate {
      email: "bad".to_string(),
      password: "short".to_string(),
      name: "".to_string(),
    };
    let err = user.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
    assert!(err.field_errors().contains_key("password"));
    assert!(err.field_errors().contains_key("name"));
  }

  #[test]
  fn test_user_create_password_exact_min() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "a".repeat(8),
      name: "Test User".to_string(),
    };
    assert!(user.validate().is_ok());
  }

  #[test]
  fn test_user_create_password_exact_max() {
    let user = UserCreate {
      email: "user@example.com".to_string(),
      password: "a".repeat(64),
      name: "Test User".to_string(),
    };
    assert!(user.validate().is_ok());
  }

  // --- Serialization tests ---

  #[test]
  fn test_user_create_serialization() {
    let user = UserCreate {
      email: "test@example.com".to_string(),
      password: "secure123".to_string(),
      name: "Test User".to_string(),
    };

    let json = serde_json::to_string(&user).unwrap();
    assert!(json.contains("\"email\":\"test@example.com\""));
    assert!(json.contains("\"password\":\"secure123\""));
    assert!(json.contains("\"name\":\"Test User\""));
  }

  #[test]
  fn test_user_create_deserialization() {
    let json = r#"{"email":"john@test.com","password":"pass456","name":"John Doe"}"#;
    let user: UserCreate = serde_json::from_str(json).unwrap();
    assert_eq!(user.email, "john@test.com");
    assert_eq!(user.password, "pass456");
    assert_eq!(user.name, "John Doe");
  }

  #[test]
  fn test_user_dto_default() {
    let dto = UserDto::default();
    assert_eq!(dto.id, "");
    assert_eq!(dto.email, "");
    assert_eq!(dto.name, "");
    assert_eq!(dto.status, "");
    assert_eq!(dto.role, "");
    assert!(dto.created_at.is_none());
    assert!(dto.updated_at.is_none());
  }

  #[test]
  fn test_user_dto_serialization() {
    let dto = UserDto {
      id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
      email: "user@test.com".to_string(),
      name: "Test User".to_string(),
      status: "Active".to_string(),
      role: "User".to_string(),
      created_at: Some("2024-01-01T00:00:00.000Z".to_string()),
      updated_at: Some("2024-01-02T00:00:00.000Z".to_string()),
    };

    let json = serde_json::to_string(&dto).unwrap();
    assert!(json.contains("\"id\":\"123e4567-e89b-12d3-a456-426614174000\""));
    assert!(json.contains("\"email\":\"user@test.com\""));
    assert!(json.contains("\"name\":\"Test User\""));
    assert!(json.contains("\"status\":\"Active\""));
    assert!(json.contains("\"role\":\"User\""));
  }

  #[test]
  fn test_user_dto_deserialization() {
    let json = r#"{
      "id":"550e8400-e29b-41d4-a716-446655440000",
      "email":"jane@example.com",
      "name":"Jane Smith",
      "status":"Inactive",
      "role":"Admin",
      "created_at":"2024-01-01T12:00:00.000Z",
      "updated_at":"2024-01-01T12:00:00.000Z"
    }"#;
    let dto: UserDto = serde_json::from_str(json).unwrap();
    assert_eq!(dto.id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(dto.email, "jane@example.com");
    assert_eq!(dto.name, "Jane Smith");
    assert_eq!(dto.status, "Inactive");
    assert_eq!(dto.role, "Admin");
    assert!(dto.created_at.is_some());
    assert!(dto.updated_at.is_some());
  }
}
