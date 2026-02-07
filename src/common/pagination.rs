use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

const DEFAULT_PER_PAGE: u64 = 20;
const MAX_PER_PAGE: u64 = 100;

/// Query parameters for pagination.
///
/// Supports two modes:
/// - **Page mode** (default): `?page=1&per_page=20`
/// - **Cursor mode**: `?cursor=<id>&per_page=20`
///
/// If `cursor` is provided, cursor mode is used. Otherwise page mode is used.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationParams {
  /// Page number (1-indexed, page mode only)
  pub page: Option<u64>,
  /// Items per page (default: 20, max: 100)
  pub per_page: Option<u64>,
  /// Cursor ID for cursor-based pagination (UUID of the last item)
  pub cursor: Option<String>,
}

impl PaginationParams {
  pub fn per_page(&self) -> u64 {
    self
      .per_page
      .unwrap_or(DEFAULT_PER_PAGE)
      .min(MAX_PER_PAGE)
      .max(1)
  }

  pub fn page(&self) -> u64 {
    self.page.unwrap_or(1).max(1)
  }

  pub fn is_cursor_mode(&self) -> bool {
    self.cursor.is_some()
  }
}

/// Paginated response wrapper for page-based pagination.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PageResponse<T: Serialize> {
  pub data: Vec<T>,
  pub meta: PageMeta,
}

/// Metadata for page-based pagination.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PageMeta {
  pub total: u64,
  pub page: u64,
  pub per_page: u64,
  pub total_pages: u64,
}

/// Paginated response wrapper for cursor-based pagination.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CursorResponse<T: Serialize> {
  pub data: Vec<T>,
  pub meta: CursorMeta,
}

/// Metadata for cursor-based pagination.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CursorMeta {
  pub per_page: u64,
  pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_per_page() {
    let params = PaginationParams {
      page: None,
      per_page: None,
      cursor: None,
    };
    assert_eq!(params.per_page(), DEFAULT_PER_PAGE);
  }

  #[test]
  fn test_per_page_clamped_to_max() {
    let params = PaginationParams {
      page: None,
      per_page: Some(200),
      cursor: None,
    };
    assert_eq!(params.per_page(), MAX_PER_PAGE);
  }

  #[test]
  fn test_per_page_clamped_to_min() {
    let params = PaginationParams {
      page: None,
      per_page: Some(0),
      cursor: None,
    };
    assert_eq!(params.per_page(), 1);
  }

  #[test]
  fn test_default_page() {
    let params = PaginationParams {
      page: None,
      per_page: None,
      cursor: None,
    };
    assert_eq!(params.page(), 1);
  }

  #[test]
  fn test_page_clamped_to_min() {
    let params = PaginationParams {
      page: Some(0),
      per_page: None,
      cursor: None,
    };
    assert_eq!(params.page(), 1);
  }

  #[test]
  fn test_is_cursor_mode() {
    let params = PaginationParams {
      page: None,
      per_page: None,
      cursor: Some("some-id".to_string()),
    };
    assert!(params.is_cursor_mode());
  }

  #[test]
  fn test_is_not_cursor_mode() {
    let params = PaginationParams {
      page: Some(2),
      per_page: None,
      cursor: None,
    };
    assert!(!params.is_cursor_mode());
  }

  #[test]
  fn test_page_meta_serialization() {
    let meta = PageMeta {
      total: 100,
      page: 1,
      per_page: 20,
      total_pages: 5,
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"total\":100"));
    assert!(json.contains("\"page\":1"));
    assert!(json.contains("\"per_page\":20"));
    assert!(json.contains("\"total_pages\":5"));
  }

  #[test]
  fn test_cursor_meta_serialization() {
    let meta = CursorMeta {
      per_page: 20,
      next_cursor: Some("abc-123".to_string()),
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"per_page\":20"));
    assert!(json.contains("\"next_cursor\":\"abc-123\""));
  }

  #[test]
  fn test_cursor_meta_no_next() {
    let meta = CursorMeta {
      per_page: 20,
      next_cursor: None,
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"next_cursor\":null"));
  }
}
