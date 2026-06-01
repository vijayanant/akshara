//! Graph handle for working with individual graphs.

pub mod core;
pub mod flush;
pub mod history;
pub mod ops;
pub mod sync;

#[cfg(feature = "schema")]
pub mod document;

#[cfg(test)]
pub mod tests;

pub use core::Graph;
pub use flush::FlushReport;
pub use history::RevisionEntry;
pub use sync::SyncReport;

#[cfg(feature = "schema")]
pub use history::DocumentVersion;

pub(crate) use crate::path::{current_timestamp, validate_path, validate_path_read};
