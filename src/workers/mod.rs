pub mod jobs;

use std::time::Duration;

use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::database::Db;

/// Everything a job needs to do its work.
#[derive(Clone)]
pub struct JobContext {
  pub db: Db,
  pub cfg: Config,
}

/// A unit of background work that runs outside the request path.
///
/// Implementations live in [`jobs`] and are listed in [`jobs::registry`], which
/// is the only place to touch when adding one.
#[async_trait::async_trait]
pub trait Job: Send + Sync {
  /// Name the job is invoked by on the command line, in kebab case.
  fn name(&self) -> &'static str;

  /// One line shown in the command listing.
  fn description(&self) -> &'static str;

  /// How long to wait between two runs in watch mode.
  fn interval(&self, cfg: &Config) -> Duration {
    Duration::from_secs(cfg.workers_interval_hours * 3600)
  }

  /// Performs one run and reports how many records it touched.
  async fn run(&self, ctx: &JobContext) -> Result<u64, ApiError>;
}

/// Runs a job once, turning a failure into a log entry.
///
/// A failed run must not take the worker down, so that a transient database
/// error does not end a watch mode process.
pub async fn run_once(job: &dyn Job, ctx: &JobContext) {
  let name = job.name();

  match job.run(ctx).await {
    Ok(affected) => tracing::info!(job = name, affected, "Job completed"),
    Err(e) => tracing::error!(job = name, error = %e, "Job failed"),
  }
}
