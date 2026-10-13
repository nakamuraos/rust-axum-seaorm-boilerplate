use async_graphql::{dynamic::*, http::GraphiQLSource};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
  Extension, Router,
  extract::State,
  response::Html,
  routing::{get, post},
};
use sea_orm::DatabaseConnection;
use seaography::{Builder, BuilderContext, async_graphql, lazy_static};

use crate::app::AppState;
use crate::common::middlewares;
use crate::modules::auth::guards::{auth_guard, graphql_guards};
use crate::modules::users::{self, dto::UserDto, entities as usersEntities, enums::UserRole};

lazy_static::lazy_static! {
  static ref CONTEXT: BuilderContext = {
    let context = BuilderContext::default();
    let hooks = graphql_guards::setup_guards();

    BuilderContext {
      hooks,
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

async fn graphql_handler(
  schema: State<Schema>,
  Extension(user): Extension<UserDto>,
  req: GraphQLRequest,
) -> GraphQLResponse {
  let role = if user.role == "Admin" {
    UserRole::Admin
  } else {
    UserRole::User
  };
  schema.execute(req.into_inner().data(role)).await.into()
}

async fn graphql_playground(State(state): State<AppState>) -> Html<String> {
  let endpoint = &state.cfg.graphql_endpoint;
  Html(GraphiQLSource::build().endpoint(endpoint).finish())
}

#[cfg(test)]
mod tests {
  #[tokio::test]
  async fn security_graphql_schema_excludes_password_hash() {
    let schema = crate::common::graphql::schema(
      sea_orm::MockDatabase::new(sea_orm::DbBackend::Postgres).into_connection(),
      None,
      None,
    )
    .unwrap();
    assert!(!schema.sdl().contains("password:"));
    let response = schema
      .execute("{ __type(name: \"Users\") { fields { name } } }")
      .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let fields = data["__type"]["fields"]
      .as_array()
      .expect("Generated Users type must exist");
    assert!(
      !fields.iter().any(|field| field["name"] == "password"),
      "Password hashes are queryable through the generated schema"
    );
  }

  #[tokio::test]
  async fn security_graphql_handler_passes_current_role() {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    for role in [UserRole::Admin, UserRole::User] {
      let query = Object::new("Query").field(Field::new(
        "admin",
        TypeRef::named_nn(TypeRef::BOOLEAN),
        |ctx| {
          let admin = ctx.data_opt::<UserRole>() == Some(&UserRole::Admin);
          FieldFuture::new(async move { Ok(Some(FieldValue::value(admin))) })
        },
      ));
      let schema = Schema::build("Query", None, None)
        .register(query)
        .finish()
        .unwrap();
      let user =
        crate::modules::auth::service::tests::user(users::enums::UserStatus::Active, role.clone());
      let app = Router::new()
        .route("/", post(graphql_handler))
        .with_state(schema)
        .layer(Extension(UserDto::from(user)));
      let response = app
        .oneshot(
          Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"query":"{ admin }"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), axum::http::StatusCode::OK);
      let body = response.into_body().collect().await.unwrap().to_bytes();
      let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
      assert_eq!(
        data,
        serde_json::json!({"data": {"admin": role == UserRole::Admin}})
      );
    }
  }
}
