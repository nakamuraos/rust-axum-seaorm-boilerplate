use axum::{
  body::Body,
  extract::State,
  response::{IntoResponse, Response},
};
use base64::{engine::general_purpose, Engine};
use hyper::StatusCode;

/// Middleware that applies basic authentication.
pub async fn basic_auth_layer(
  State(state): State<crate::app::AppState>,
  req: axum::http::Request<Body>,
  next: axum::middleware::Next,
) -> Result<Response<Body>, StatusCode> {
  let auth_header = req.headers().get("authorization");

  if let Some(header_value) = auth_header {
    if let Ok(auth_str) = header_value.to_str() {
      if auth_str.starts_with("Basic ") {
        let encoded = &auth_str[6..];
        if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
          if let Ok(decoded_str) = String::from_utf8(decoded) {
            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            let config_parts: Vec<&str> = state.cfg.graphql_basic_auth.split(':').collect();
            let username = config_parts[0].to_string();
            let password = config_parts[1].to_string();
            if parts.len() == 2 && parts[0] == username && parts[1] == password {
              return Ok(next.run(req).await);
            }
          }
        }
      }
    }
  }

  let mut response = StatusCode::UNAUTHORIZED.into_response();
  response.headers_mut().insert(
    "WWW-Authenticate",
    "Basic realm=\"Restricted\"".parse().unwrap(),
  );
  Ok(response)
}
