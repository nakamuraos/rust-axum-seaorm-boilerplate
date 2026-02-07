use axum::{
  extract::rejection::JsonRejection,
  response::{IntoResponse, Response},
  Json,
};
use hyper::StatusCode;
use sea_orm::DbErr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

/// Custom error type for the API.
/// The `#[from]` attribute allows for easy conversion from other error types.
#[derive(Error, Debug)]
pub enum ApiError {
  /// Converts from an Axum built-in extractor error.
  #[error("Invalid payload.")]
  InvalidJsonBody(#[from] JsonRejection),

  /// For errors that occur during manual validation.
  #[error("Invalid request: {0}")]
  InvalidRequest(String),

  /// For errors that occur during manual validation.
  #[error("Not Found: {0}")]
  NotFound(String),

  /// For errors that occur when a user tries to access a resource they are not allowed to.
  #[error("Forbidden: {0}")]
  Forbidden(String),

  /// For errors that occur when a user tries to access a resource they are not authorized to.
  #[error("Unauthorized: {0}")]
  Unauthorized(String),

  /// Converts from `sea_orm::DbErr`.
  #[error("A database error has occurred.")]
  DatabaseError(#[from] DbErr),

  /// Converts from any `anyhow::Error`.
  #[error("An internal server error has occurred.")]
  InternalError(#[from] anyhow::Error),
}

#[derive(Serialize, Deserialize)]
pub struct ApiErrorResp {
  pub status: u16,
  pub message: String,
}

// The IntoResponse implementation for ApiError logs the error message.
//
// To avoid exposing implementation details to API consumers, we separate
// the message that we log from the API response message.
impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    // Log detailed error for telemetry.
    let error_to_log = match &self {
      ApiError::InvalidJsonBody(ref err) => match err {
        JsonRejection::JsonDataError(e) => e.body_text(),
        JsonRejection::JsonSyntaxError(e) => e.body_text(),
        JsonRejection::MissingJsonContentType(_) => {
          "Missing `Content-Type: application/json` header".to_string()
        }
        JsonRejection::BytesRejection(_) => "Failed to buffer request body".to_string(),
        _ => "Unknown error".to_string(),
      },
      ApiError::InvalidRequest(_) => format!("{}", self),
      ApiError::NotFound(_) => format!("{}", self),
      ApiError::Forbidden(_) => format!("{}", self),
      ApiError::Unauthorized(_) => format!("{}", self),
      ApiError::DatabaseError(ref err) => format!("{}", err),
      ApiError::InternalError(ref err) => format!("{}", err),
    };
    error!("{}", error_to_log);

    // Determine the appropriate status code.
    let status = match self {
      ApiError::InvalidJsonBody(_) | ApiError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
      ApiError::NotFound(_) => StatusCode::NOT_FOUND,
      ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
      ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
      ApiError::DatabaseError(_) | ApiError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    // Create a generic response to hide specific implementation details.
    let resp = ApiErrorResp {
      status: status.as_u16(),
      message: self.to_string(),
    };

    (status, Json(resp)).into_response()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_api_error_invalid_request() {
    let error = ApiError::InvalidRequest("Test error".to_string());
    assert_eq!(error.to_string(), "Invalid request: Test error");
  }

  #[test]
  fn test_api_error_not_found() {
    let error = ApiError::NotFound("Resource not found".to_string());
    assert_eq!(error.to_string(), "Not Found: Resource not found");
  }

  #[test]
  fn test_api_error_forbidden() {
    let error = ApiError::Forbidden("Access denied".to_string());
    assert_eq!(error.to_string(), "Forbidden: Access denied");
  }

  #[test]
  fn test_api_error_unauthorized() {
    let error = ApiError::Unauthorized("Not authenticated".to_string());
    assert_eq!(error.to_string(), "Unauthorized: Not authenticated");
  }

  #[test]
  fn test_api_error_response_status_codes() {
    let invalid_request = ApiError::InvalidRequest("Test".to_string());
    let response = invalid_request.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let not_found = ApiError::NotFound("Test".to_string());
    let response = not_found.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let forbidden = ApiError::Forbidden("Test".to_string());
    let response = forbidden.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let unauthorized = ApiError::Unauthorized("Test".to_string());
    let response = unauthorized.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_api_error_resp_serialization() {
    let error_resp = ApiErrorResp {
      status: 400,
      message: "Bad Request".to_string(),
    };

    let json = serde_json::to_string(&error_resp).unwrap();
    assert!(json.contains("\"status\":400"));
    assert!(json.contains("\"message\":\"Bad Request\""));
  }

  #[test]
  fn test_api_error_resp_deserialization() {
    let json = r#"{"status":404,"message":"Not Found"}"#;
    let error_resp: ApiErrorResp = serde_json::from_str(json).unwrap();
    assert_eq!(error_resp.status, 404);
    assert_eq!(error_resp.message, "Not Found");
  }
}
