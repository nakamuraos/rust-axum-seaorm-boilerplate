use async_graphql::dynamic::ResolverContext;
use seaography::{GuardAction, LifecycleHooks, LifecycleHooksInterface, OperationType};

use crate::modules::users::enums::UserRole;

/// Lifecycle hooks that enforce role-based access on GraphQL entities and fields.
pub struct GraphqlGuards;

fn require_admin(ctx: &ResolverContext) -> GuardAction {
  if ctx.data_opt::<UserRole>() == Some(&UserRole::Admin) {
    return GuardAction::Allow;
  }
  GuardAction::Block(Some("Admin role required".to_string()))
}

impl LifecycleHooksInterface for GraphqlGuards {
  fn entity_guard(
    &self,
    ctx: &ResolverContext,
    entity: &str,
    _action: OperationType,
  ) -> GuardAction {
    if matches!(entity, "Users" | "UsersBasic") {
      return require_admin(ctx);
    }
    GuardAction::Block(Some("Unknown entity".to_string()))
  }

  fn field_guard(
    &self,
    ctx: &ResolverContext,
    entity: &str,
    field: &str,
    _action: OperationType,
  ) -> GuardAction {
    if matches!(entity, "Users" | "UsersBasic") && (field == "role" || field == "status") {
      return require_admin(ctx);
    }
    GuardAction::Allow
  }
}

pub fn setup_guards() -> LifecycleHooks {
  tracing::info!("Setting up GraphQL guards");
  LifecycleHooks::new(GraphqlGuards)
}

#[cfg(test)]
mod tests {
  use async_graphql::{
    Request, Value,
    dynamic::{Field, FieldFuture, FieldValue, Object, Schema, TypeRef},
  };
  use seaography::{
    BuilderContext, EntityObjectBuilder, GuardAction, LifecycleHooksInterface, OperationType,
  };

  use crate::modules::auth::guards::graphql_guards::GraphqlGuards;
  use crate::modules::users::{entities::Entity, enums::UserRole};

  seaography::lazy_static::lazy_static! {
    static ref CONTEXT: BuilderContext = BuilderContext::default();
  }

  async fn allowed(role: Option<UserRole>, field: Option<&str>, action: OperationType) -> bool {
    let entity = EntityObjectBuilder { context: &CONTEXT }.type_name::<Entity>();
    let field = field.map(str::to_owned);
    let query = Object::new("Query").field(Field::new(
      "allowed",
      TypeRef::named_nn(TypeRef::BOOLEAN),
      move |ctx| {
        let decision = match &field {
          Some(field) => GraphqlGuards.field_guard(&ctx, &entity, field, action),
          None => GraphqlGuards.entity_guard(&ctx, &entity, action),
        };
        FieldFuture::new(async move {
          Ok(Some(FieldValue::value(matches!(
            decision,
            GuardAction::Allow
          ))))
        })
      },
    ));
    let schema = Schema::build("Query", None, None)
      .register(query)
      .finish()
      .unwrap();
    let mut request = Request::new("{ allowed }");
    if let Some(role) = role {
      request = request.data(role);
    }
    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    response.data == Value::from_json(serde_json::json!({"allowed": true})).unwrap()
  }

  #[tokio::test]
  async fn security_graphql_user_entity_requires_admin() {
    for role in [None, Some(UserRole::User)] {
      for action in [
        OperationType::Read,
        OperationType::Create,
        OperationType::Update,
        OperationType::Delete,
      ] {
        assert!(
          !allowed(role.clone(), None, action).await,
          "{role:?} can perform {action:?} on the generated user entity"
        );
      }
    }
  }

  #[tokio::test]
  async fn security_graphql_sensitive_fields_require_admin() {
    for field in ["role", "status"] {
      for action in [
        OperationType::Read,
        OperationType::Create,
        OperationType::Update,
      ] {
        assert!(
          !allowed(Some(UserRole::User), Some(field), action).await,
          "A regular user can perform {action:?} on {field}"
        );
      }
    }
  }

  #[tokio::test]
  async fn security_graphql_admin_is_allowed() {
    for action in [
      OperationType::Read,
      OperationType::Create,
      OperationType::Update,
      OperationType::Delete,
    ] {
      assert!(allowed(Some(UserRole::Admin), None, action).await);
    }
  }
}
