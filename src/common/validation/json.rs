use axum::{
  extract::{rejection::JsonRejection, FromRequest, Request},
  Json,
};
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::common::api_error::ApiError;

/// A custom JSON extractor that validates the request body after deserialization.
///
/// Use this instead of `Json<T>` when `T` implements `Validate`.
pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
  T: DeserializeOwned + Validate,
  S: Send + Sync,
  Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
  type Rejection = ApiError;

  async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
    let Json(value) = Json::<T>::from_request(req, state).await?;
    value.validate().map_err(|e| {
      let messages: Vec<String> = e
        .field_errors()
        .into_iter()
        .flat_map(|(field, errors)| {
          errors.iter().map(move |err| {
            err
              .message
              .as_ref()
              .map(|m| format!("{}: {}", field, m))
              .unwrap_or_else(|| format!("{}: validation failed", field))
          })
        })
        .collect();
      ApiError::InvalidRequest(messages.join(", "))
    })?;
    Ok(ValidatedJson(value))
  }
}
