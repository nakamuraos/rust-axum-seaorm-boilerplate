use async_graphql::{dynamic, http::GraphiQLSource};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
  extract::State,
  response::Html,
  routing::{get, post},
  Router,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::{BasicAuth, Config as SwaggerConfig, SwaggerUi};

use crate::common::utils;
use crate::common::{cfg::Config, middlewares, telemetry};
use crate::database::Db;
use crate::doc;
use crate::modules::{self, auth::guards::auth_guard};
use crate::query_root;

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
  let api_doc = SwaggerUi::new(app_state.cfg.swagger_endpoint.clone())
    .url(
      app_state.cfg.swagger_endpoint.clone() + "/api-doc/openapi.json",
      doc::ApiDoc::openapi(),
    )
    .config({
      let mut config = SwaggerConfig::default().persist_authorization(true);
      if !app_state.cfg.swagger_basic_auth.is_empty() {
        let parts: Vec<&str> = app_state.cfg.swagger_basic_auth.split(':').collect();
        if parts.len() == 2 {
          config = config.basic_auth(BasicAuth {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
          });
        } else {
          panic!("Invalid format for swagger_basic_auth. Expected 'username:password'.");
        }
      }
      config
    });

  // Create the GraphQL schema using the query root.
  let schema = query_root::schema(app_state.db.conn.clone(), None, None).unwrap();
  let graphql_router = Router::new().nest(
    &app_state.cfg.graphql_endpoint,
    Router::new()
      .merge({
        let mut router = Router::new().route("/", get(graphql_playground));
        if !app_state.cfg.graphql_basic_auth.is_empty() {
          let parts: Vec<&str> = app_state.cfg.graphql_basic_auth.split(':').collect();
          if parts.len() == 2 {
            router = router.layer(axum::middleware::from_fn({
              let auth_config = app_state.clone();
              move |req, next| {
                let auth_config = auth_config.clone();
                async move { utils::auth::basic_auth_layer(State(auth_config), req, next).await }
              }
            }));
          } else {
            panic!("Invalid format for graphql_basic_auth. Expected 'username:password'.");
          }
        }
        router
      })
      .merge(
        Router::new()
          .route("/", post(graphql_handler))
          .with_state(schema)
          .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_guard,
          )),
      ),
  );

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

async fn graphql_handler(
  schema: axum::extract::State<dynamic::Schema>,
  req: GraphQLRequest,
) -> GraphQLResponse {
  schema.execute(req.into_inner()).await.into()
}

async fn graphql_playground(State(state): State<AppState>) -> Html<String> {
  let endpoint = &state.cfg.graphql_endpoint;
  Html(GraphiQLSource::build().endpoint(endpoint).finish())
}
