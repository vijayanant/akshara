//! Staging store for buffering operations before sealing.
//!
//! Operations are staged, coalesced, and then sealed into the Merkle-DAG.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::Mutex;

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
}

impl StagedOperation {
    /// Get the path for this operation.
    pub fn path(&self) -> &str {
        match self {
            Self::Insert { path, .. } | Self::Update { path, .. } | Self::Delete { path, .. } => {
                path
            }
        }
    }

    /// Get the timestamp for this operation.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Insert { timestamp, .. }
            | Self::Update { timestamp, .. }
            | Self::Delete { timestamp, .. } => *timestamp,
        }
    }
}

/// Staging store trait for buffering operations.
///
/// Implementations should use interior mutability (e.g., `Arc<Mutex<>>`).
#[async_trait::async_trait]
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
                StagedOperation::Delete { .. } => 0,
            })
            .sum();
        Ok(size)
    }
}

/// Coalesce operations by path.
///
/// Later operations to the same path override earlier ones.
pub fn coalesce_operations(operations: Vec<StagedOperation>) -> Vec<StagedOperation> {
    let mut by_path: BTreeMap<String, StagedOperation> = BTreeMap::new();

    for op in operations {
        let path = op.path().to_string();

        match op {
            StagedOperation::Insert { .. } | StagedOperation::Update { .. } => {
                // Insert/Update replaces any prior operation at same path
                by_path.insert(path, op);
            }
            StagedOperation::Delete { .. } => {
                // Delete clears any prior operations at same path
                by_path.insert(path, op);
            }
        }
    }

    by_path.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Unit Tests: StagedOperation
    // ========================================================================

    #[test]
    fn staged_operation_path() {
        let insert = StagedOperation::Insert {
            path: "/test".to_string(),
            data: vec![1, 2, 3],
            timestamp: 1,
        };
        assert_eq!(insert.path(), "/test");

        let delete = StagedOperation::Delete {
            path: "/test".to_string(),
            timestamp: 1,
        };
        assert_eq!(delete.path(), "/test");
    }

    #[test]
    fn staged_operation_timestamp() {
        let op = StagedOperation::Insert {
            path: "/test".to_string(),
            data: vec![],
            timestamp: 42,
        };
        assert_eq!(op.timestamp(), 42);
    }

    // ========================================================================
    // Unit Tests: coalesce_operations
    // ========================================================================

    #[test]
    fn coalesce_empty() {
        let ops: Vec<StagedOperation> = vec![];
        let result = coalesce_operations(ops);
        assert!(result.is_empty());
    }

    #[test]
    fn coalesce_single_operation() {
        let ops = vec![StagedOperation::Insert {
            path: "/test".to_string(),
            data: vec![1],
            timestamp: 1,
        }];
        let result = coalesce_operations(ops);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn coalesce_update_same_path() {
        let ops = vec![
            StagedOperation::Insert {
                path: "/doc".to_string(),
                data: vec![1],
                timestamp: 1,
            },
            StagedOperation::Update {
                path: "/doc".to_string(),
                data: vec![2],
                timestamp: 2,
            },
            StagedOperation::Update {
                path: "/doc".to_string(),
                data: vec![3],
                timestamp: 3,
            },
        ];
        let result = coalesce_operations(ops);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].timestamp(), 3);
    }

    #[test]
    fn coalesce_delete_clears_prior_ops() {
        let ops = vec![
            StagedOperation::Insert {
                path: "/doc".to_string(),
                data: vec![1],
                timestamp: 1,
            },
            StagedOperation::Delete {
                path: "/doc".to_string(),
                timestamp: 2,
            },
        ];
        let result = coalesce_operations(ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], StagedOperation::Delete { .. }));
    }

    #[test]
    fn coalesce_different_paths_preserved() {
        let ops = vec![
            StagedOperation::Insert {
                path: "/doc1".to_string(),
                data: vec![1],
                timestamp: 1,
            },
            StagedOperation::Insert {
                path: "/doc2".to_string(),
                data: vec![2],
                timestamp: 2,
            },
        ];
        let result = coalesce_operations(ops);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn coalesce_delete_then_insert() {
        let ops = vec![
            StagedOperation::Delete {
                path: "/doc".to_string(),
                timestamp: 1,
            },
            StagedOperation::Insert {
                path: "/doc".to_string(),
                data: vec![1],
                timestamp: 2,
            },
        ];
        let result = coalesce_operations(ops);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], StagedOperation::Insert { .. }));
    }

    // ========================================================================
    // Integration Tests: InMemoryStagingStore
    // ========================================================================

    #[tokio::test]
    async fn stage_and_fetch() {
        let store = InMemoryStagingStore::new();
        store
            .stage_operation(StagedOperation::Insert {
                path: "/test".to_string(),
                data: b"hello".to_vec(),
                timestamp: 1,
            })
            .await
            .unwrap();

        let ops = store.fetch_pending().await.unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[tokio::test]
    async fn clear_committed() {
        let store = InMemoryStagingStore::new();

        store
            .stage_operation(StagedOperation::Insert {
                path: "/test1".to_string(),
                data: b"hello".to_vec(),
                timestamp: 1,
            })
            .await
            .unwrap();

        store
            .stage_operation(StagedOperation::Insert {
                path: "/test2".to_string(),
                data: b"world".to_vec(),
                timestamp: 2,
            })
            .await
            .unwrap();

        store.clear_committed(1).await.unwrap();

        let ops = store.fetch_pending().await.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].path(), "/test2");
    }

    #[tokio::test]
    async fn pending_count() {
        let store = InMemoryStagingStore::new();
        assert_eq!(store.pending_count().await.unwrap(), 0);

        store
            .stage_operation(StagedOperation::Insert {
                path: "/test".to_string(),
                data: b"hello".to_vec(),
                timestamp: 1,
            })
            .await
            .unwrap();

        assert_eq!(store.pending_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn pending_size() {
        let store = InMemoryStagingStore::new();
        assert_eq!(store.pending_size().await.unwrap(), 0);

        store
            .stage_operation(StagedOperation::Insert {
                path: "/test".to_string(),
                data: b"hello".to_vec(),
                timestamp: 1,
            })
            .await
            .unwrap();

        assert_eq!(store.pending_size().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn delete_has_zero_size() {
        let store = InMemoryStagingStore::new();

        store
            .stage_operation(StagedOperation::Delete {
                path: "/test".to_string(),
                timestamp: 1,
            })
            .await
            .unwrap();

        assert_eq!(store.pending_count().await.unwrap(), 1);
        assert_eq!(store.pending_size().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn clear_all() {
        let store = InMemoryStagingStore::new();

        for i in 1..=5 {
            store
                .stage_operation(StagedOperation::Insert {
                    path: format!("/test{}", i),
                    data: vec![i as u8],
                    timestamp: i,
                })
                .await
                .unwrap();
        }

        store.clear_committed(100).await.unwrap();
        let ops = store.fetch_pending().await.unwrap();
        assert!(ops.is_empty());
    }

    #[tokio::test]
    async fn concurrent_stage_operations() {
        use std::sync::Arc;

        let store = Arc::new(Mutex::new(InMemoryStagingStore::new()));
        let mut handles = vec![];

        for i in 0..100 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                let s = store_clone.lock().await;
                s.stage_operation(StagedOperation::Insert {
                    path: format!("/test{}", i),
                    data: vec![i as u8],
                    timestamp: i,
                })
                .await
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let s = store.lock().await;
        let ops = s.fetch_pending().await.unwrap();
        assert_eq!(ops.len(), 100);
    }
}
