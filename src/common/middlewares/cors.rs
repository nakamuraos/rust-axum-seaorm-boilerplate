use std::time::Duration;

use tower_http::cors::{AllowHeaders, Any, CorsLayer};

/// Layer that applies the Cors middleware which adds headers for CORS.
pub fn cors_layer() -> CorsLayer {
  CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(AllowHeaders::mirror_request())
    .max_age(Duration::from_secs(600))
}
