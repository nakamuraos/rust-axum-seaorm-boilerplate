use serde_yaml_ng::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Default location of the YAML configuration file, relative to the working directory.
pub const DEFAULT_CONFIG_PATH: &str = "config/config.yml";

/// Environment variable pointing at an alternative configuration file.
pub const CONFIG_PATH_VAR: &str = "CONFIG";

/// A configuration file flattened into dotted paths, e.g. `database.url`.
///
/// Nesting is purely cosmetic: a key is addressed by the path of the mapping
/// keys leading to it, whatever depth it sits at.
#[derive(Debug, Default)]
pub struct FileConfig {
  values: BTreeMap<String, String>,
  read: RefCell<HashSet<String>>,
}

impl FileConfig {
  /// Loads the configuration file.
  ///
  /// The path comes from the caller, then from `CONFIG`, then from the default
  /// location. An explicitly requested file must exist; the default one is
  /// optional, so the application can run without a configuration file at all.
  pub fn load(explicit_path: Option<&Path>) -> Self {
    let explicit = explicit_path
      .map(PathBuf::from)
      .or_else(|| std::env::var(CONFIG_PATH_VAR).ok().map(PathBuf::from));

    let required = explicit.is_some();
    let path = explicit.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    let contents = match std::fs::read_to_string(&path) {
      Ok(contents) => contents,
      Err(err) => {
        if required {
          panic!(
            "Unable to read configuration file {}: {}",
            path.display(),
            err
          );
        }
        return Self::default();
      }
    };

    let root: Value = serde_yaml_ng::from_str(&contents).unwrap_or_else(|e| {
      panic!(
        "Unable to parse configuration file {}: {}",
        path.display(),
        e
      )
    });

    let mut values = BTreeMap::new();
    flatten(&root, String::new(), &mut values);

    Self {
      values,
      read: RefCell::new(HashSet::new()),
    }
  }

  /// Returns the raw value at a dotted path.
  pub fn get(&self, path: &str) -> Option<&str> {
    self.read.borrow_mut().insert(path.to_string());
    self.values.get(path).map(String::as_str)
  }

  /// Logs the keys the application never looked at, which are typically typos.
  pub fn warn_unknown_keys(&self) {
    let read = self.read.borrow();
    let unknown: Vec<&str> = self
      .values
      .keys()
      .map(String::as_str)
      .filter(|key| !read.contains(*key))
      .collect();

    if !unknown.is_empty() {
      warn!(keys = ?unknown, "Ignoring unknown configuration file keys");
    }
  }
}

/// Walks a YAML tree and records every scalar leaf under its dotted path.
fn flatten(value: &Value, prefix: String, out: &mut BTreeMap<String, String>) {
  match value {
    Value::Mapping(mapping) => {
      for (key, child) in mapping {
        let Some(key) = key.as_str() else { continue };
        let path = if prefix.is_empty() {
          key.to_string()
        } else {
          format!("{}.{}", prefix, key)
        };
        flatten(child, path, out);
      }
    }
    Value::Null => {}
    Value::String(s) => {
      out.insert(prefix, s.clone());
    }
    Value::Bool(b) => {
      out.insert(prefix, b.to_string());
    }
    Value::Number(n) => {
      out.insert(prefix, n.to_string());
    }
    Value::Sequence(_) | Value::Tagged(_) => {}
  }
}
