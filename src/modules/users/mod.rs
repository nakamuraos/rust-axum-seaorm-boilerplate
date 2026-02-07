pub mod controller;
pub mod dto;
pub mod entities;
pub mod enums;
pub mod service;

use axum::{
  extract::State,
  routing::{delete, get, post, put},
  Router,
};

use crate::app::AppState;
use crate::modules::auth::guards::{admin_guard, admin_or_owner_guard, auth_guard};

pub fn router(State(state): State<AppState>) -> axum::Router<AppState> {
  // Admin-only routes: list all users, create user
  let admin_routes = Router::new()
    .route("/", get(controller::index))
    .route("/", post(controller::create))
    .layer(axum::middleware::from_fn(admin_guard));

  // Admin or owner routes: show, update, delete own profile
  let owner_routes = Router::new()
    .route("/{user_id}", get(controller::show))
    .route("/{user_id}", put(controller::update))
    .route("/{user_id}", delete(controller::destroy))
    .layer(axum::middleware::from_fn(admin_or_owner_guard));

  // All routes require authentication
  Router::new()
    .nest(
      "/v1/users",
      Router::new().merge(admin_routes).merge(owner_routes),
    )
    .layer(axum::middleware::from_fn_with_state(state, auth_guard))
}
