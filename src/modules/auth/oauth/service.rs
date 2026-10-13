use super::{
  Profile, Provider, account,
  dto::{AuthorizationResponse, CallbackQuery, CallbackResponse},
  flow::{self, Flow, Intent},
  github,
};
use crate::common::{config::Config, errors::ApiError};
use crate::modules::{
  auth::{dto::LinkIdentityRequest, service::ensure_active, service::ownership},
  users::entities as users,
};
use axum::{
  Json,
  http::header,
  response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use sea_orm::{DatabaseConnection, EntityTrait};
use uuid::Uuid;

pub(crate) async fn login(cfg: &Config, provider: &str) -> Result<Authorization, ApiError> {
  authorize(cfg, provider, Intent::Login).await
}

async fn authorize(
  cfg: &Config,
  provider: &str,
  intent: Intent,
) -> Result<Authorization, ApiError> {
  let provider = parse(provider)?;
  let callback_url = callback_url(cfg, provider);

  let (url, mut flow) = match provider {
    Provider::Github => github::authorize(cfg, callback_url)?,
    #[cfg(feature = "oidc")]
    Provider::Google | Provider::Oidc => {
      let settings = super::oidc::settings(cfg, provider == Provider::Google)?;
      super::oidc::authorize(
        &settings,
        &super::oidc::http()?,
        callback_url,
        !matches!(intent, Intent::Login),
      )
      .await?
    }
  };

  flow.intent = intent;
  let cookie = flow.to_cookie(cfg)?;
  Ok(Authorization {
    url,
    cookie,
    login: matches!(flow.intent, Intent::Login),
  })
}

pub(crate) async fn callback(
  conn: &DatabaseConnection,
  cfg: &Config,
  provider: &str,
  query: CallbackQuery,
  cookie_header: Option<&str>,
) -> Result<CallbackResponse, ApiError> {
  let provider = parse(provider)?;

  if let Some(error) = query.error {
    return Err(ApiError::Unauthorized(format!(
      "Provider refused the login: {}",
      error
    )));
  }
  let (Some(code), Some(returned_state)) = (query.code, query.state) else {
    return Err(ApiError::InvalidRequest(
      "Missing code or state".to_string(),
    ));
  };

  let flow = Flow::from_cookie_header(cfg, cookie_header)?;
  if flow.provider != provider.as_str() || flow.state != returned_state {
    return Err(ApiError::Unauthorized(
      "Invalid or expired OAuth state".to_string(),
    ));
  }

  let callback_url = callback_url(cfg, provider);
  let profile: Profile = match provider {
    Provider::Github => github::profile(cfg, callback_url, code, &flow).await?,
    #[cfg(feature = "oidc")]
    Provider::Google | Provider::Oidc => {
      let settings = super::oidc::settings(cfg, provider == Provider::Google)?;
      super::oidc::profile(&settings, &super::oidc::http()?, callback_url, code, &flow).await?
    }
  };

  let outcome = match flow.intent {
    Intent::Login => CallbackResponse::Session(
      account::sign_in(conn, cfg, provider.as_str(), profile)
        .await?
        .into(),
    ),
    Intent::Link { proof_token } => CallbackResponse::Session(
      account::link_identity(conn, cfg, &proof_token, provider.as_str(), profile)
        .await?
        .into(),
    ),
    Intent::Verify {
      user_id,
      session_version,
    } => CallbackResponse::Proof(
      account::verify_identity(
        conn,
        cfg,
        user_id,
        session_version,
        provider.as_str(),
        profile,
      )
      .await?,
    ),
  };
  Ok(outcome)
}

fn parse(name: &str) -> Result<Provider, ApiError> {
  Provider::parse(name).ok_or_else(|| ApiError::NotFound("Unknown provider".to_string()))
}

fn callback_url(cfg: &Config, provider: Provider) -> String {
  format!(
    "{}/api/v1/auth/oauth/{}/callback",
    cfg.oauth.redirect_base_url.trim_end_matches('/'),
    provider.as_str()
  )
}

pub(crate) async fn link(
  cfg: &Config,
  user_id: Uuid,
  provider: &str,
  req: LinkIdentityRequest,
) -> Result<Authorization, ApiError> {
  let proof = ownership::verify(cfg, &req.proof_token)?;
  if proof.user_id != user_id {
    return Err(ApiError::Unauthorized(
      "Proof belongs to another account".into(),
    ));
  }
  authorize(
    cfg,
    provider,
    Intent::Link {
      proof_token: req.proof_token,
    },
  )
  .await
}

pub(crate) async fn verify(
  conn: &DatabaseConnection,
  cfg: &Config,
  user_id: Uuid,
  provider: &str,
) -> Result<Authorization, ApiError> {
  let account = users::Entity::find_by_id(user_id)
    .one(conn)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Account no longer exists".into()))?;
  ensure_active(&account.status)?;
  authorize(
    cfg,
    provider,
    Intent::Verify {
      user_id,
      session_version: account.session_version,
    },
  )
  .await
}

pub(crate) struct Authorization {
  pub url: String,
  pub cookie: String,
  pub login: bool,
}

impl IntoResponse for Authorization {
  fn into_response(self) -> Response {
    let headers = AppendHeaders([
      (header::SET_COOKIE, self.cookie),
      (header::CACHE_CONTROL, "no-store".into()),
    ]);
    if self.login {
      (headers, Redirect::temporary(&self.url)).into_response()
    } else {
      (
        headers,
        Json(AuthorizationResponse {
          authorization_url: self.url,
        }),
      )
        .into_response()
    }
  }
}

impl CallbackResponse {
  pub(crate) fn into_callback(self, cfg: &Config) -> Response {
    let headers = AppendHeaders([
      (header::SET_COOKIE, flow::clear_cookie(cfg)),
      (header::CACHE_CONTROL, "no-store".into()),
    ]);
    let target = &cfg.oauth.success_redirect_url;
    if target.is_empty() {
      return (headers, Json(self)).into_response();
    }
    // Fragments keep credentials out of HTTP requests and server logs.
    let url = match self {
      Self::Session(auth) => format!(
        "{}#token={}&refresh_token={}",
        target, auth.token, auth.refresh_token
      ),
      Self::Proof(proof) => format!(
        "{}#account_proof={}&user_id={}",
        target, proof.proof_token, proof.user_id
      ),
    };
    (headers, Redirect::to(&url)).into_response()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::config::tests::config;
  use crate::modules::{
    auth::dto::{AuthResponse, OwnershipProofResponse},
    users::dto::UserDto,
  };
  use axum::{body::to_bytes, http::StatusCode};
  #[tokio::test]
  async fn test_callback_response_preserves_json_shapes_and_clears_flow() {
    let cfg = config();
    let proof = OwnershipProofResponse {
      user_id: uuid::Uuid::new_v4(),
      proof_token: "proof-token".into(),
      expires_in: 300,
    };
    let response = CallbackResponse::Proof(proof).into_callback(&cfg);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
      response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0")
    );
    let json: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(json["proof_token"], "proof-token");
    assert!(json.get("token").is_none());
    let response = CallbackResponse::Session(Box::new(AuthResponse {
      token: "access".into(),
      refresh_token: "refresh".into(),
      user: UserDto::default(),
    }))
    .into_callback(&cfg);
    let json: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(json["token"], "access");
    assert_eq!(json["refresh_token"], "refresh");
    assert!(json.get("proof_token").is_none());
  }

  #[test]
  fn test_callback_redirect_keeps_proof_in_fragment() {
    let mut cfg = config();
    std::sync::Arc::get_mut(&mut cfg)
      .unwrap()
      .oauth
      .success_redirect_url = "https://app.example.com/auth".into();
    let id = uuid::Uuid::new_v4();
    let response = CallbackResponse::Proof(OwnershipProofResponse {
      user_id: id,
      proof_token: "proof-token".into(),
      expires_in: 300,
    })
    .into_callback(&cfg);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
      response.headers()[header::LOCATION],
      format!("https://app.example.com/auth#account_proof=proof-token&user_id={id}")
    );
  }
}
