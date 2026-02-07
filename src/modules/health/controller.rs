use axum::Json;

use crate::modules::health::{dto::Healthy, service};

#[utoipa::path(
  get,
  tag = "Health",
  path = "/api/v1/health",
  operation_id = "healthIndex",
  responses(
      (status = 200, description = "Health check", body = Healthy)
  )
)]
pub async fn index() -> Json<Healthy> {
  let result = service::index().await;
  Json(result)
}
