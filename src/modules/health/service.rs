use crate::modules::health::dto::Healthy;

pub async fn index() -> Healthy {
  Healthy {
    status: "ok".to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_health_index_returns_ok() {
    let result = index().await;
    assert_eq!(result.status, "ok");
  }

  #[tokio::test]
  async fn test_health_index_has_status_field() {
    let result = index().await;
    assert!(!result.status.is_empty());
  }
}
