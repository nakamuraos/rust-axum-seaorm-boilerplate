use axum::{
  extract::{rejection::PathRejection, FromRequestParts, Path},
  http::request::Parts,
};
use serde::de::DeserializeOwned;

use crate::common::errors::ApiError;

/// A custom Path extractor that returns `ApiError` on rejection.
///
/// Use this instead of `Path<T>` to get consistent error responses
/// through the `ApiError` system.
pub struct ValidatedPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ValidatedPath<T>
where
  T: DeserializeOwned + Send,
  S: Send + Sync,
{
  type Rejection = ApiError;

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    match Path::<T>::from_request_parts(parts, state).await {
      Ok(Path(value)) => Ok(ValidatedPath(value)),
      Err(rejection) => Err(path_rejection_to_api_error(rejection)),
    }
  }
}

fn path_rejection_to_api_error(rejection: PathRejection) -> ApiError {
  match rejection {
    PathRejection::FailedToDeserializePathParams(inner) => {
      ApiError::InvalidRequest(inner.body_text())
    }
    PathRejection::MissingPathParams(inner) => ApiError::InvalidRequest(inner.body_text()),
    _ => ApiError::InvalidRequest("Invalid path parameter".to_string()),
  }
}
