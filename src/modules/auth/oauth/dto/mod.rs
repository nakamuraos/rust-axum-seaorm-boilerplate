use crate::modules::auth::dto::{AuthResponse, OwnershipProofResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct AuthorizationResponse {
  pub authorization_url: String,
}

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum CallbackResponse {
  Session(Box<AuthResponse>),
  Proof(OwnershipProofResponse),
}

#[derive(Deserialize)]
pub struct CallbackQuery {
  pub(crate) code: Option<String>,
  pub(crate) state: Option<String>,
  /// Set by the provider instead of `code` when the user refuses or it fails.
  pub(crate) error: Option<String>,
}
