pub mod cleanup_tokens;

use super::Job;

/// Every job the worker binary can run.
///
/// Adding a job means writing a module next to `cleanup_tokens` and listing it
/// here; the command line, the listing and watch mode pick it up from there.
pub fn registry() -> Vec<Box<dyn Job>> {
  vec![Box::new(cleanup_tokens::CleanupTokens)]
}

/// Looks up a job by the name it is invoked by.
pub fn find(name: &str) -> Option<Box<dyn Job>> {
  registry().into_iter().find(|job| job.name() == name)
}
