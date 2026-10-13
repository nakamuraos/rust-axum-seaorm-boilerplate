use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::common::{config::Config, errors::ApiError};
use crate::modules::auth::{dto::OwnershipProofResponse, service::ensure_active};
use crate::modules::users::entities;

pub(crate) const PROOF_TTL_SECONDS: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OwnershipProof {
  pub user_id: Uuid,
  pub session_version: i64,
  exp: usize,
}

impl OwnershipProof {
  pub fn check_user(&self, user: &entities::Model) -> Result<(), ApiError> {
    ensure_active(&user.status)?;
    if self.exp <= chrono::Utc::now().timestamp() as usize
      || self.user_id != user.id
      || self.session_version != user.session_version
    {
      return Err(ApiError::Unauthorized(
        "Account proof is no longer valid".into(),
      ));
    }
    Ok(())
  }
}

pub(crate) fn issue(
  cfg: &Config,
  user: &entities::Model,
) -> Result<OwnershipProofResponse, ApiError> {
  ensure_active(&user.status)?;
  let proof = OwnershipProof {
    user_id: user.id,
    session_version: user.session_version,
    exp: (chrono::Utc::now().timestamp() + PROOF_TTL_SECONDS) as usize,
  };
  let proof_token = encode(
    &Header::default(),
    &proof,
    &EncodingKey::from_secret(&signing_key(cfg)),
  )
  .map_err(|e| ApiError::InternalError(e.into()))?;
  Ok(OwnershipProofResponse {
    user_id: user.id,
    proof_token,
    expires_in: PROOF_TTL_SECONDS as u64,
  })
}

pub(crate) fn verify(cfg: &Config, token: &str) -> Result<OwnershipProof, ApiError> {
  decode::<OwnershipProof>(
    token,
    &DecodingKey::from_secret(&signing_key(cfg)),
    &Validation {
      leeway: 0,
      ..Validation::default()
    },
  )
  .map(|data| data.claims)
  .map_err(|_| ApiError::Unauthorized("Invalid or expired account proof".into()))
}

fn signing_key(cfg: &Config) -> Vec<u8> {
  let mut digest = Sha256::new();
  digest.update(b"account-ownership:");
  digest.update(cfg.jwt_secret.expose().as_bytes());
  digest.finalize().to_vec()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::modules::auth::service::{generate_token, tests::user};
  use crate::modules::users::enums::{UserRole, UserStatus};

  #[test]
  fn test_proof_is_bound_to_user_and_session_version() {
    let cfg = config();
    let mut user = user(UserStatus::Active, UserRole::User);
    let token = issue(&cfg, &user).unwrap();
    let proof = verify(&cfg, &token.proof_token).unwrap();
    proof.check_user(&user).unwrap();
    user.session_version += 1;
    assert!(proof.check_user(&user).is_err());
    user.session_version -= 1;
    user.id = Uuid::new_v4();
    assert!(proof.check_user(&user).is_err());
  }

  #[test]
  fn test_access_tokens_and_ownership_proofs_are_not_interchangeable() {
    let cfg = config();
    let user = user(UserStatus::Active, UserRole::User);
    assert!(verify(&cfg, &generate_token(&user, &cfg).unwrap()).is_err());
    let token = issue(&cfg, &user).unwrap();
    assert!(
      decode::<crate::modules::auth::guards::auth_guard::Claims>(
        &token.proof_token,
        &DecodingKey::from_secret(cfg.jwt_secret.expose().as_bytes()),
        &Validation::default(),
      )
      .is_err()
    );
  }

  #[test]
  fn test_expired_and_tampered_proofs_are_rejected() {
    let cfg = config();
    let user = user(UserStatus::Active, UserRole::User);
    let token = issue(&cfg, &user).unwrap();
    assert!(verify(&cfg, &format!("{}x", token.proof_token)).is_err());
    let expired = OwnershipProof {
      user_id: user.id,
      session_version: 0,
      exp: (chrono::Utc::now().timestamp() - 1) as usize,
    };
    assert!(expired.check_user(&user).is_err());
    let token = encode(
      &Header::default(),
      &expired,
      &EncodingKey::from_secret(&signing_key(&cfg)),
    )
    .unwrap();
    assert!(verify(&cfg, &token).is_err());
  }
}
