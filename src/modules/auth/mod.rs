pub mod controller;
pub mod dto;
pub mod entities;
pub mod guards;
#[cfg(feature = "oauth2")]
pub mod oauth;
pub mod service;

use axum::{
  Router,
  extract::State,
  routing::{get, post},
};

use crate::app::AppState;
use crate::modules::auth::guards::auth_guard;

pub fn router(State(state): State<AppState>) -> Router<AppState> {
  // These routes act on the caller rather than on a presented token, so they
  // are the ones behind the auth guard.
  let authenticated_routes = Router::new()
    .route("/v1/auth/logout-all", post(controller::logout_all))
    .route("/v1/auth/sessions", get(controller::sessions))
    .layer(axum::middleware::from_fn_with_state(state, auth_guard));

  let router = Router::new()
    .route("/v1/auth/register", post(controller::register))
    .route("/v1/auth/login", post(controller::login))
    .route("/v1/auth/refresh", post(controller::refresh))
    .route("/v1/auth/logout", post(controller::logout))
    .merge(authenticated_routes);

  #[cfg(feature = "oauth2")]
  let router = router.merge(oauth::router());

  router
}
