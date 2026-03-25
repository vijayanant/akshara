//! Fractional indexing for ordered sequences.
//!
//! This module provides a simple wrapper around the `fractional_index` crate.
//!
//! # Purpose
//!
//! In a content-addressed DAG, renaming items in a list (e.g., using integer
//! indices like `/1`, `/2`) is expensive because it changes the CIDs of all
//! subsequent items.
//!
//! Fractional indexing allows for arbitrary insertions between existing items
//! by generating a lexicographical "midpoint" string. This ensures that only
//! the inserted item receives a new CID, enabling perfect structural sharing
//! for the rest of the list.

use crate::error::{Error, Result};
pub use fractional_index::FractionalIndex;

/// Generates a midpoint string between two optional index strings.
///
/// This is a convenience utility for working with path-based ordered sequences.
pub fn midpoint(prev: Option<&str>, next: Option<&str>) -> Result<String> {
    let p_idx = prev.map(parse_index).transpose()?;
    let n_idx = next.map(parse_index).transpose()?;

    let new_idx = match (p_idx, n_idx) {
        (Some(p), Some(n)) => FractionalIndex::new_between(&p, &n).ok_or_else(|| {
            Error::Protocol(akshara_aadhaara::AksharaError::InternalError(
                "Indices too close".to_string(),
            ))
        })?,
        (Some(p), None) => FractionalIndex::new_after(&p),
        (None, Some(n)) => FractionalIndex::new_before(&n),
        (None, None) => FractionalIndex::default(),
    };

    Ok(new_idx.to_string())
}

/// Helper to parse a string back into a FractionalIndex.
pub(crate) fn parse_index(s: &str) -> Result<FractionalIndex> {
    FractionalIndex::from_string(s).map_err(|e| {
        Error::Protocol(akshara_aadhaara::AksharaError::InternalError(format!(
            "Invalid index format ({}): {}",
            s, e
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_midpoint_utility() {
        let first = midpoint(None, None).unwrap();
        let second = midpoint(Some(&first), None).unwrap();
        let between = midpoint(Some(&first), Some(&second)).unwrap();

        assert!(first < between);
        assert!(between < second);
    }
}
