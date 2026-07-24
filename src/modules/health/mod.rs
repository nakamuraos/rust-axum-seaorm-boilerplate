pub mod controller;
pub mod dto;
pub mod service;

use axum::Router;
use axum_extra::routing::Resource;

use crate::app::AppState;

pub fn router() -> axum::Router<AppState> {
  let resources_v1 = Resource::named("health").index(controller::index);

  Router::new().nest("/v1", Router::new().merge(resources_v1))
}
