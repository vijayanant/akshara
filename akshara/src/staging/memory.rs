use std::sync::Arc;
use tokio::sync::Mutex;

use super::{StagedOperation, StagingStore};
use crate::error::Result;

/// In-memory staging store implementation.
pub struct InMemoryStagingStore {
    operations: Arc<Mutex<Vec<StagedOperation>>>,
}

impl InMemoryStagingStore {
    /// Create a new in-memory staging store.
    pub fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for InMemoryStagingStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StagingStore for InMemoryStagingStore {
    async fn stage_operation(&self, op: StagedOperation) -> Result<()> {
        let mut ops = self.operations.lock().await;
        ops.push(op);
        Ok(())
    }

    async fn fetch_pending(&self) -> Result<Vec<StagedOperation>> {
        let ops = self.operations.lock().await;
        Ok(ops.clone())
    }

    async fn clear_committed(&self, up_to_timestamp: u64) -> Result<()> {
        let mut ops = self.operations.lock().await;
        ops.retain(|op| op.timestamp() > up_to_timestamp);
        Ok(())
    }

    async fn pending_count(&self) -> Result<usize> {
        let ops = self.operations.lock().await;
        Ok(ops.len())
    }

    async fn pending_size(&self) -> Result<usize> {
        let ops = self.operations.lock().await;
        let size = ops
            .iter()
            .map(|op| match op {
                StagedOperation::Insert { data, .. } | StagedOperation::Update { data, .. } => {
                    data.len()
                }
                StagedOperation::Delete { .. } | StagedOperation::Link { .. } => 0,
            })
            .sum();
        Ok(size)
    }
}
