use async_graphql::dynamic::ResolverContext;
use seaography::{GuardAction, LifecycleHooks, LifecycleHooksInterface, OperationType};

use crate::modules::users::enums::UserRole;

/// Lifecycle hooks that enforce role-based access on GraphQL entities and fields.
pub struct GraphqlGuards;

fn require_admin(ctx: &ResolverContext) -> GuardAction {
  // Get the user role from the context
  tracing::info!("Context data: {:?}", ctx.data::<UserRole>());
  if let Some(role) = ctx.data_opt::<UserRole>() {
    if *role == UserRole::Admin {
      return GuardAction::Allow;
    }
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
    if entity == "users" {
      return require_admin(ctx);
    }
    GuardAction::Allow
  }

  fn field_guard(
    &self,
    ctx: &ResolverContext,
    entity: &str,
    field: &str,
    _action: OperationType,
  ) -> GuardAction {
    if entity == "users" && (field == "role" || field == "status") {
      return require_admin(ctx);
    }
    GuardAction::Allow
  }
}

pub fn setup_guards() -> LifecycleHooks {
  tracing::info!("Setting up GraphQL guards");
  LifecycleHooks::new(GraphqlGuards)
}
