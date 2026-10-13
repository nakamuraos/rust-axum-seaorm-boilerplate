use std::sync::{Arc, LazyLock};

use tokio::sync::Semaphore;

use crate::common::errors::ApiError;

static WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

async fn run<T, F>(workers: Arc<Semaphore>, work: F) -> Result<T, ApiError>
where
  T: Send + 'static,
  F: FnOnce() -> Result<T, bcrypt::BcryptError> + Send + 'static,
{
  let permit = workers
    .try_acquire_owned()
    .map_err(|_| ApiError::TooManyRequests)?;
  tokio::task::spawn_blocking(move || {
    // The worker holds the permit even when the waiting request is cancelled.
    let _permit = permit;
    work()
  })
  .await
  .map_err(|e| ApiError::InternalError(e.into()))?
  .map_err(|e| ApiError::InternalError(e.into()))
}

pub(crate) async fn hash(password: String, cost: u32) -> Result<String, ApiError> {
  run(WORKERS.clone(), move || bcrypt::hash(password, cost)).await
}

pub(crate) async fn verify(password: String, hash: String) -> Result<bool, ApiError> {
  run(WORKERS.clone(), move || bcrypt::verify(password, &hash)).await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn security_password_work_rejects_overload() {
    let workers = Arc::new(Semaphore::new(1));
    let _permit = workers.acquire().await.unwrap();
    let result = run(workers.clone(), || Ok(())).await;
    assert!(matches!(result, Err(ApiError::TooManyRequests)));
  }

  #[tokio::test]
  async fn security_password_work_does_not_block_runtime() {
    let workers = Arc::new(Semaphore::new(1));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(run(workers, move || {
      started_tx.send(()).unwrap();
      release_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
      Ok(())
    }));
    started_rx.await.unwrap();
    release_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn security_password_cancellation_keeps_worker_bounded() {
    let workers = Arc::new(Semaphore::new(1));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(run(workers.clone(), move || {
      started_tx.send(()).unwrap();
      release_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
      finished_tx.send(()).unwrap();
      Ok(())
    }));
    started_rx.await.unwrap();
    task.abort();
    assert!(matches!(
      run(workers, || Ok(())).await,
      Err(ApiError::TooManyRequests)
    ));
    release_tx.send(()).unwrap();
    finished_rx.await.unwrap();
  }
}
