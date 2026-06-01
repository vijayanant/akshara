//! Staging store for buffering operations before sealing.
//!
//! Operations are staged, coalesced, and then sealed into the Merkle-DAG.

pub mod coalesce;
pub mod memory;

#[cfg(test)]
pub mod tests;

pub use coalesce::coalesce_operations;
pub use memory::InMemoryStagingStore;

use crate::error::Result;

/// A staged operation pending commit.
#[derive(Debug, Clone)]
pub enum StagedOperation {
    /// Insert new content at path
    Insert {
        path: String,
        data: Vec<u8>,
        timestamp: u64,
    },
    /// Update existing content at path
    Update {
        path: String,
        data: Vec<u8>,
        timestamp: u64,
    },
    /// Delete content at path
    Delete { path: String, timestamp: u64 },
    /// Link an existing Address at path (used by document adapters)
    Link {
        path: String,
        address: akshara_aadhaara::Address,
        timestamp: u64,
    },
}

impl StagedOperation {
    /// Get the path for this operation.
    pub fn path(&self) -> &str {
        match self {
            Self::Insert { path, .. }
            | Self::Update { path, .. }
            | Self::Delete { path, .. }
            | Self::Link { path, .. } => path,
        }
    }

    /// Get the timestamp for this operation.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Insert { timestamp, .. }
            | Self::Update { timestamp, .. }
            | Self::Delete { timestamp, .. }
            | Self::Link { timestamp, .. } => *timestamp,
        }
    }
}

/// Staging store trait for buffering operations.
///
/// Implementations should use interior mutability (e.g., `Arc<Mutex<>>`).
#[allow(async_fn_in_trait)]
pub trait StagingStore: Send + Sync {
    /// Stage an operation for later sealing.
    async fn stage_operation(&self, op: StagedOperation) -> Result<()>;

    /// Fetch all pending operations.
    async fn fetch_pending(&self) -> Result<Vec<StagedOperation>>;

    /// Clear operations that have been committed.
    async fn clear_committed(&self, up_to_timestamp: u64) -> Result<()>;

    /// Get the number of pending operations.
    async fn pending_count(&self) -> Result<usize>;

    /// Get the total size of pending data.
    async fn pending_size(&self) -> Result<usize>;
}
