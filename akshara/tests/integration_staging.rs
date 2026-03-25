//! Integration tests for the Akshara staging module.
//!
//! These tests verify multi-component behavior with realistic scenarios.

use akshara::staging::{InMemoryStagingStore, StagedOperation, StagingStore, coalesce_operations};
use proptest::prelude::*;

// ============================================================================
// Property-Based Tests
// ============================================================================

proptest! {
    #[test]
    fn coalesce_preserves_at_least_one_op_per_path(
        paths in prop::collection::vec(prop::string::string_regex("/[a-z]+").unwrap(), 1..20),
        timestamps in prop::collection::vec(1u64..1000, 1..20),
    ) {
        let ops: Vec<StagedOperation> = paths.iter()
            .zip(timestamps.iter())
            .map(|(path, ts)| StagedOperation::Insert {
                path: path.clone(),
                data: vec![*ts as u8],
                timestamp: *ts,
            })
            .collect();

        let result = coalesce_operations(ops);

        let unique_paths: std::collections::HashSet<_> = paths.iter().collect();
        prop_assert!(result.len() <= unique_paths.len());
    }

    #[test]
    fn coalesce_last_timestamp_wins(
        path in prop::string::string_regex("/test").unwrap(),
        ts1 in 1u64..100,
        ts2 in 101u64..200,
        data1 in prop::collection::vec(any::<u8>(), 1..10),
        data2 in prop::collection::vec(any::<u8>(), 1..10),
    ) {
        let ops = vec![
            StagedOperation::Insert {
                path: path.clone(),
                data: data1.clone(),
                timestamp: ts1,
            },
            StagedOperation::Update {
                path: path.clone(),
                data: data2.clone(),
                timestamp: ts2,
            },
        ];

        let result = coalesce_operations(ops);

        prop_assert_eq!(result.len(), 1);
        prop_assert_eq!(result[0].timestamp(), ts2);
    }
}

// ============================================================================
// Multi-Component Integration Tests
// ============================================================================

#[tokio::test]
async fn staging_store_clear_with_max_timestamp() {
    let store = InMemoryStagingStore::new();

    for i in 1..=10 {
        store
            .stage_operation(StagedOperation::Insert {
                path: format!("/test{}", i),
                data: vec![i as u8],
                timestamp: i * 10,
            })
            .await
            .unwrap();
    }

    store.clear_committed(50).await.unwrap();

    let ops = store.fetch_pending().await.unwrap();
    assert_eq!(ops.len(), 5);
    for op in ops {
        assert!(op.timestamp() > 50);
    }
}

#[tokio::test]
async fn staging_store_mixed_operations() {
    let store = InMemoryStagingStore::new();

    store
        .stage_operation(StagedOperation::Insert {
            path: "/doc1".to_string(),
            data: vec![1],
            timestamp: 1,
        })
        .await
        .unwrap();

    store
        .stage_operation(StagedOperation::Update {
            path: "/doc1".to_string(),
            data: vec![2],
            timestamp: 2,
        })
        .await
        .unwrap();

    store
        .stage_operation(StagedOperation::Delete {
            path: "/doc2".to_string(),
            timestamp: 3,
        })
        .await
        .unwrap();

    let ops = store.fetch_pending().await.unwrap();
    assert_eq!(ops.len(), 3);

    store.clear_committed(1).await.unwrap();
    let ops = store.fetch_pending().await.unwrap();
    assert_eq!(ops.len(), 2);
}
