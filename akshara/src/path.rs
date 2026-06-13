//! Path validation and utility functions.

use crate::error::{Error, Result};

/// Validate a path string for read operations, allowing reserved `.akshara.*` segments.
pub fn validate_path_read(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must start with /".to_string(),
        });
    }
    if path.contains('\0') {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not contain null bytes".to_string(),
        });
    }
    if path.len() > 1024 {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not exceed 1024 characters".to_string(),
        });
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not contain relative path segments (. or ..)".to_string(),
        });
    }
    Ok(())
}

/// Validate a path string.
///
/// Paths must start with `/`, contain no null bytes, and not exceed 1024
/// characters. Reserved `.akshara.*` segments are also rejected.
pub fn validate_path(path: &str) -> Result<()> {
    validate_path_read(path)?;
    if path.split('/').any(|seg| seg.starts_with(".akshara.")) {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not use reserved .akshara.* segments".to_string(),
        });
    }
    Ok(())
}

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
