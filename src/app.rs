use axum::Router;

use crate::common::{api_doc, config::telemetry, config::Config, graphql, middlewares};
use crate::database::Db;
use crate::modules;

#[derive(Clone)]
pub struct AppState {
  pub db: Db,
  pub cfg: Config,
}

pub fn router(cfg: Config, db: Db) -> Router {
  let app_state = AppState { db, cfg };

  // Middleware that adds high level tracing to a Service.
  // Trace comes with good defaults but also supports customizing many aspects of the output:
  // https://docs.rs/tower-http/latest/tower_http/trace/index.html
  let trace_layer = telemetry::trace_layer();

  // Sets 'x-request-id' header with randomly generated uuid v7.
  let request_id_layer = middlewares::request_id_layer();

  // Propagates 'x-request-id' header from the request to the response.
  let propagate_request_id_layer = middlewares::propagate_request_id_layer();

  // Layer that applies the Cors middleware which adds headers for CORS.
  let cors_layer = middlewares::cors_layer();

  // Layer that applies the Timeout middleware, which sets a timeout for requests.
  // The default value is 15 seconds.
  let timeout_layer = middlewares::timeout_layer();

  // Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
  // will be changed to `/foo` before reaching the internal service.
  let normalize_path_layer = middlewares::normalize_path_layer();

  // Create the router with the routes.
  let router = modules::router(axum::extract::State(app_state.clone()));

  // Create the API documentation using OpenAPI and Swagger UI.
  let api_doc = api_doc::swagger_ui(&app_state.cfg);

  // Create the GraphQL router with playground and query handler.
  let graphql_router = graphql::router(app_state.clone());

  // Combine all the routes and apply the middleware layers.
  // The order of the layers is important. The first layer is the outermost layer.
  Router::new()
    .merge(router)
    .merge(api_doc)
    .merge(graphql_router)
    .layer(normalize_path_layer)
    .layer(cors_layer)
    .layer(timeout_layer)
    .layer(propagate_request_id_layer)
    .layer(trace_layer)
    .layer(request_id_layer)
    .with_state(app_state)
}
