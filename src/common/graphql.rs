use async_graphql::{dynamic::*, http::GraphiQLSource};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
  extract::State,
  response::Html,
  routing::{get, post},
  Router,
};
use sea_orm::DatabaseConnection;
use seaography::{async_graphql, lazy_static, Builder, BuilderContext};

use crate::app::AppState;
use crate::common::middlewares;
use crate::modules::auth::guards::{auth_guard, graphql_guards};
use crate::modules::users::{self, entities as usersEntities};

lazy_static::lazy_static! {
  static ref CONTEXT: BuilderContext = {
    let context = BuilderContext::default();
    let guards = graphql_guards::setup_guards();

    BuilderContext {
      guards,
      ..context
    }
  };
}

pub fn schema(
  database: DatabaseConnection,
  depth: Option<usize>,
  complexity: Option<usize>,
) -> Result<Schema, SchemaError> {
  // Create a new schema builder with the provided database connection
  let mut builder = Builder::new(&CONTEXT, database.clone());

  // Register the entities
  seaography::register_entities!(builder, [usersEntities]);

  // Register the active enums
  builder.register_enumeration::<users::enums::UserStatus>();
  builder.register_enumeration::<users::enums::UserRole>();

  // Register the custom scalars
  builder
    .set_depth_limit(depth)
    .set_complexity_limit(complexity)
    .schema_builder()
    .data(database)
    .finish()
}

/// Create the GraphQL router with playground and query handler.
pub fn router(app_state: AppState) -> Router<AppState> {
  let schema = schema(app_state.db.conn.clone(), None, None).unwrap();
  Router::new().nest(
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
                async move {
                  middlewares::basic_auth::basic_auth_layer(State(auth_config), req, next).await
                }
              }
            }));
          } else {
            // We're immediately panicking here because this is a configuration error that should be
            // caught during application startup.
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
  )
}

async fn graphql_handler(schema: State<Schema>, req: GraphQLRequest) -> GraphQLResponse {
  schema.execute(req.into_inner()).await.into()
}

async fn graphql_playground(State(state): State<AppState>) -> Html<String> {
  let endpoint = &state.cfg.graphql_endpoint;
  Html(GraphiQLSource::build().endpoint(endpoint).finish())
}
