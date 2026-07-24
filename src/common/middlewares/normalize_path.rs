use tower_http::normalize_path::NormalizePathLayer;

/// Middleware that normalizes paths.
///
/// Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
/// will be changed to `/foo` before reaching the inner service.
pub fn normalize_path_layer() -> NormalizePathLayer {
  NormalizePathLayer::trim_trailing_slash()
}
