use axum::{Extension, Json, extract::State};

use crate::app::AppState;
use crate::common::errors::ApiError;
use crate::common::extractors::ValidatedJson;
use crate::modules::auth::dto::{
  AuthResponse, LoginRequest, LogoutResponse, RefreshRequest, RegisterRequest, SessionDto,
  TokenPairResponse,
};
use crate::modules::auth::service;
use uuid::Uuid;

use super::dto::{
  LinkedIdentityDto, MergeAccountsRequest, MergePreviewResponse, OwnershipProofRequest,
  OwnershipProofResponse,
};
use super::service::accounts;

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/register",
  operation_id = "authRegister",
  request_body = RegisterRequest,
  responses(
    (status = 200, description = "Register successful", body = AuthResponse),
    (status = 400, description = "Validation error"),
    (status = 409, description = "Email already exists"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn register(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
  let result = service::register(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/login",
  operation_id = "authLogin",
  request_body = LoginRequest,
  responses(
    (status = 200, description = "Login successful", body = AuthResponse),
    (status = 400, description = "Validation error"),
    (status = 401, description = "Invalid credentials"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn login(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
  let result = service::login(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/refresh",
  operation_id = "authRefresh",
  request_body = RefreshRequest,
  responses(
    (status = 200, description = "New token pair issued", body = TokenPairResponse),
    (status = 400, description = "Validation error"),
    (status = 401, description = "Invalid or expired refresh token"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn refresh(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<TokenPairResponse>, ApiError> {
  let result = service::refresh(&state.db.conn, &state.cfg, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/logout",
  operation_id = "authLogout",
  request_body = RefreshRequest,
  responses(
    (status = 200, description = "Refresh token revoked", body = LogoutResponse),
    (status = 400, description = "Validation error"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn logout(
  State(state): State<AppState>,
  ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<LogoutResponse>, ApiError> {
  let result = service::logout(&state.db.conn, req).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/logout-all",
  operation_id = "authLogoutAll",
  security(("bearer_auth" = [])),
  responses(
    (status = 200, description = "All refresh tokens revoked", body = LogoutResponse),
    (status = 401, description = "Unauthorized"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn logout_all(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
) -> Result<Json<LogoutResponse>, ApiError> {
  let result = service::logout_all(&state.db.conn, user_id).await?;
  Ok(Json(result))
}

#[utoipa::path(
  get,
  tag = "Auth",
  path = "/api/v1/auth/sessions",
  operation_id = "authSessions",
  security(("bearer_auth" = [])),
  responses(
    (status = 200, description = "Logins of the authenticated user", body = Vec<SessionDto>),
    (status = 401, description = "Unauthorized"),
    (status = 500, description = "Internal server error")
  )
)]
pub async fn sessions(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
) -> Result<Json<Vec<SessionDto>>, ApiError> {
  let result = service::sessions(&state.db.conn, user_id).await?;
  Ok(Json(result))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/accounts/proof",
  operation_id = "authAccountProof",
  security(("bearerAuth" = [])),
  request_body = OwnershipProofRequest,
  responses(
    (status = 200, description = "Short-lived proof of password ownership", body = OwnershipProofResponse),
    (status = 401, description = "Invalid credentials")
  )
)]
pub async fn account_proof(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
  ValidatedJson(req): ValidatedJson<OwnershipProofRequest>,
) -> Result<Json<OwnershipProofResponse>, ApiError> {
  Ok(Json(
    accounts::password_proof(&state.db.conn, &state.cfg, user_id, req.password).await?,
  ))
}

#[utoipa::path(
  get,
  tag = "Auth",
  path = "/api/v1/auth/accounts/identities",
  operation_id = "authAccountIdentities",
  security(("bearerAuth" = [])),
  responses(
    (status = 200, description = "Connected provider identities", body = Vec<LinkedIdentityDto>),
    (status = 401, description = "Unauthorized")
  )
)]
pub async fn identities(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
) -> Result<Json<Vec<LinkedIdentityDto>>, ApiError> {
  Ok(Json(accounts::identities(&state.db.conn, user_id).await?))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/accounts/merge/preview",
  operation_id = "authAccountMergePreview",
  security(("bearerAuth" = [])),
  request_body = MergeAccountsRequest,
  responses(
    (status = 200, description = "Accounts, identities, conflicts and consequences", body = MergePreviewResponse),
    (status = 401, description = "Invalid account proofs")
  )
)]
pub async fn merge_preview(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
  ValidatedJson(req): ValidatedJson<MergeAccountsRequest>,
) -> Result<Json<MergePreviewResponse>, ApiError> {
  Ok(Json(
    accounts::preview(&state.db.conn, &state.cfg, user_id, &req).await?,
  ))
}

#[utoipa::path(
  post,
  tag = "Auth",
  path = "/api/v1/auth/accounts/merge",
  operation_id = "authAccountMerge",
  security(("bearerAuth" = [])),
  request_body = MergeAccountsRequest,
  responses(
    (status = 200, description = "Merged into the authenticated target with a new session", body = AuthResponse),
    (status = 400, description = "Confirmation required"),
    (status = 401, description = "Invalid account proofs"),
    (status = 403, description = "Conflicting roles")
  )
)]
pub async fn merge_accounts(
  State(state): State<AppState>,
  Extension(user_id): Extension<Uuid>,
  ValidatedJson(req): ValidatedJson<MergeAccountsRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
  Ok(Json(
    accounts::merge(&state.db.conn, &state.cfg, user_id, req).await?,
  ))
}
