use crate::common::errors::ApiError;
use crate::modules::auth::service;
use crate::workers::{Job, JobContext};

/// Deletes refresh tokens that can no longer be exchanged.
pub struct CleanupTokens;

#[async_trait::async_trait]
impl Job for CleanupTokens {
  fn name(&self) -> &'static str {
    "cleanup-tokens"
  }

  fn description(&self) -> &'static str {
    "Delete expired and long revoked refresh tokens"
  }

  async fn run(&self, ctx: &JobContext) -> Result<u64, ApiError> {
    service::cleanup_tokens(&ctx.db.conn, ctx.cfg.token_retention_days).await
  }
}
