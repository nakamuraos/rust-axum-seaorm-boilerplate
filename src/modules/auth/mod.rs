pub mod controller;
pub mod dto;
pub mod guards;
pub mod service;

use axum::Router;

use crate::app::AppState;

pub fn router() -> Router<AppState> {
  Router::new()
    .route(
      "/v1/auth/register",
      axum::routing::post(controller::register),
    )
    .route("/v1/auth/login", axum::routing::post(controller::login))
}
