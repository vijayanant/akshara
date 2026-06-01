#[cfg(test)]
use super::{InMemoryStagingStore, StagedOperation, StagingStore, coalesce_operations};

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
    use tokio::sync::Mutex;

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
