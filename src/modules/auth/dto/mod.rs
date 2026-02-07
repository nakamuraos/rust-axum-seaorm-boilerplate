use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::modules::users::dto::UserDto;

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
  #[validate(email(message = "invalid email format"))]
  pub email: String,
  #[validate(length(min = 8, max = 64, message = "must be between 8 and 64 characters"))]
  pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
pub struct RegisterRequest {
  #[validate(email(message = "invalid email format"))]
  pub email: String,
  #[validate(length(min = 8, max = 64, message = "must be between 8 and 64 characters"))]
  pub password: String,
  #[validate(length(min = 1, max = 100, message = "must be between 1 and 100 characters"))]
  pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
  pub token: String,
  pub user: UserDto,
}

#[cfg(test)]
mod tests {
  use super::*;
  use validator::Validate;

  // --- LoginRequest validation tests ---

  #[test]
  fn test_login_valid() {
    let req = LoginRequest {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
    };
    assert!(req.validate().is_ok());
  }

  #[test]
  fn test_login_invalid_email() {
    let req = LoginRequest {
      email: "not-an-email".to_string(),
      password: "password123".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
  }

  #[test]
  fn test_login_empty_email() {
    let req = LoginRequest {
      email: "".to_string(),
      password: "password123".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
  }

  #[test]
  fn test_login_password_too_short() {
    let req = LoginRequest {
      email: "user@example.com".to_string(),
      password: "short".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("password"));
  }

  #[test]
  fn test_login_password_too_long() {
    let req = LoginRequest {
      email: "user@example.com".to_string(),
      password: "a".repeat(65),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("password"));
  }

  #[test]
  fn test_login_all_fields_invalid() {
    let req = LoginRequest {
      email: "bad".to_string(),
      password: "short".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
    assert!(err.field_errors().contains_key("password"));
  }

  // --- RegisterRequest validation tests ---

  #[test]
  fn test_register_valid() {
    let req = RegisterRequest {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "John Doe".to_string(),
    };
    assert!(req.validate().is_ok());
  }

  #[test]
  fn test_register_invalid_email() {
    let req = RegisterRequest {
      email: "not-valid".to_string(),
      password: "password123".to_string(),
      name: "John Doe".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
  }

  #[test]
  fn test_register_password_too_short() {
    let req = RegisterRequest {
      email: "user@example.com".to_string(),
      password: "short".to_string(),
      name: "John Doe".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("password"));
  }

  #[test]
  fn test_register_name_empty() {
    let req = RegisterRequest {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("name"));
  }

  #[test]
  fn test_register_name_too_long() {
    let req = RegisterRequest {
      email: "user@example.com".to_string(),
      password: "password123".to_string(),
      name: "a".repeat(101),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("name"));
  }

  #[test]
  fn test_register_all_fields_invalid() {
    let req = RegisterRequest {
      email: "bad".to_string(),
      password: "short".to_string(),
      name: "".to_string(),
    };
    let err = req.validate().unwrap_err();
    assert!(err.field_errors().contains_key("email"));
    assert!(err.field_errors().contains_key("password"));
    assert!(err.field_errors().contains_key("name"));
  }

  // --- Serialization tests ---

  #[test]
  fn test_login_request_serialization() {
    let login_req = LoginRequest {
      email: "test@example.com".to_string(),
      password: "password123".to_string(),
    };

    let json = serde_json::to_string(&login_req).unwrap();
    assert!(json.contains("\"email\":\"test@example.com\""));
    assert!(json.contains("\"password\":\"password123\""));
  }

  #[test]
  fn test_login_request_deserialization() {
    let json = r#"{"email":"user@test.com","password":"secret"}"#;
    let login_req: LoginRequest = serde_json::from_str(json).unwrap();
    assert_eq!(login_req.email, "user@test.com");
    assert_eq!(login_req.password, "secret");
  }

  #[test]
  fn test_register_request_serialization() {
    let register_req = RegisterRequest {
      email: "newuser@example.com".to_string(),
      password: "securepass".to_string(),
      name: "John Doe".to_string(),
    };

    let json = serde_json::to_string(&register_req).unwrap();
    assert!(json.contains("\"email\":\"newuser@example.com\""));
    assert!(json.contains("\"password\":\"securepass\""));
    assert!(json.contains("\"name\":\"John Doe\""));
  }

  #[test]
  fn test_register_request_deserialization() {
    let json = r#"{"email":"jane@test.com","password":"pass123","name":"Jane Smith"}"#;
    let register_req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(register_req.email, "jane@test.com");
    assert_eq!(register_req.password, "pass123");
    assert_eq!(register_req.name, "Jane Smith");
  }
}
