pub mod auth;
pub mod health;
pub mod users;

use axum::{Router, extract::State};

use crate::app::AppState;

pub fn router(State(state): State<AppState>) -> Router<AppState> {
  let router_auth: Router<AppState> = auth::router();
  let router_health: Router<AppState> = health::router();
  let router_users: Router<AppState> = users::router(axum::extract::State(state));

  let routers: Router<AppState> = Router::new()
    .merge(router_auth)
    .merge(router_health)
    .merge(router_users);

  Router::new().nest("/api", routers)
}
