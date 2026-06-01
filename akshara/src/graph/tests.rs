#[cfg(test)]
use super::{Graph, validate_path, validate_path_read};
use crate::config::{ClientConfig, TuningConfig};
use crate::error::Error;
use crate::staging::InMemoryStagingStore;
use crate::vault::create_vault;
use akshara_aadhaara::{GraphId, GraphStore, InMemoryStore, SecretIdentity};
use std::sync::Arc;

async fn create_test_graph() -> Graph {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let config = ClientConfig::new().with_ephemeral_vault();
    let vault = create_vault(config.vault().clone()).unwrap();
    vault.initialize(Some(mnemonic)).await.unwrap();

    let identity = vault.get_identity(None).await.unwrap();
    let store = InMemoryStore::new();
    let graph_id = GraphId::new();
    let graph_key = identity.derive_graph_key(&graph_id).unwrap();

    Graph::new(
        graph_id,
        graph_key,
        vault,
        store,
        Arc::new(InMemoryStagingStore::new()),
        TuningConfig::default(),
    )
}

#[tokio::test]
async fn test_block_lineage_is_preserved_during_flush() {
    let graph = create_test_graph().await;
    let path = "/test/lineage";

    // 1. Initial write
    graph.insert(path, b"v1").await.unwrap();
    graph.flush().await.unwrap();
    let id1 = graph.get_id(path).await.unwrap();

    // 2. Update the same path
    graph.update(path, b"v2").await.unwrap();
    graph.flush().await.unwrap();
    let id2 = graph.get_id(path).await.unwrap();

    // 3. Verify that the new block points to the old block as its parent
    let block2 = graph
        .store
        .get_block(&id2)
        .await
        .unwrap()
        .expect("Block 2 should exist");

    assert_ne!(id1, id2, "Block IDs must change when content changes");
    assert!(
        block2.parents().contains(&id1),
        "Updated block should list previous version {} as parent. Found: {:?}",
        id1,
        block2.parents()
    );
}

#[tokio::test]
async fn test_multi_generation_lineage() {
    let graph = create_test_graph().await;
    let path = "/test/generations";

    // G1
    graph.insert(path, b"gen1").await.unwrap();
    graph.flush().await.unwrap();
    let id1 = graph.get_id(path).await.unwrap();

    // G2
    graph.update(path, b"gen2").await.unwrap();
    graph.flush().await.unwrap();
    let id2 = graph.get_id(path).await.unwrap();

    // G3
    graph.update(path, b"gen3").await.unwrap();
    graph.flush().await.unwrap();
    let id3 = graph.get_id(path).await.unwrap();

    // Verify G3 points to G2
    let b3 = graph.store.get_block(&id3).await.unwrap().unwrap();
    assert!(b3.parents().contains(&id2));

    // Verify G2 points to G1
    let b2 = graph.store.get_block(&id2).await.unwrap().unwrap();
    assert!(b2.parents().contains(&id1));
}

#[tokio::test]
async fn test_lineage_after_deletion_and_reinsertion() {
    let graph = create_test_graph().await;
    let path = "/test/reset";

    // 1. Insert and Flush
    graph.insert(path, b"first").await.unwrap();
    graph.flush().await.unwrap();
    let id1 = graph.get_id(path).await.unwrap();

    // 2. Delete and Flush
    graph.delete(path).await.unwrap();
    graph.flush().await.unwrap();
    assert!(
        graph.get_id(path).await.is_err(),
        "Path should be gone after delete"
    );

    // 3. Re-insert and Flush
    graph.insert(path, b"second").await.unwrap();
    graph.flush().await.unwrap();
    let id2 = graph.get_id(path).await.unwrap();

    // 4. Verify that re-insertion starts a NEW lineage (no parents)
    let b2 = graph.store.get_block(&id2).await.unwrap().unwrap();
    assert!(
        b2.parents().is_empty(),
        "Re-insertion after deletion should have no parents"
    );
    assert_ne!(id1, id2);
}

#[tokio::test]
async fn test_coalesced_update_lineage() {
    let graph = create_test_graph().await;
    let path = "/test/coalesce";

    // 1. Initial stable state
    graph.insert(path, b"original").await.unwrap();
    graph.flush().await.unwrap();
    let id_orig = graph.get_id(path).await.unwrap();

    // 2. Stage multiple updates BEFORE flushing
    graph.update(path, b"temp1").await.unwrap();
    graph.update(path, b"temp2").await.unwrap();
    graph.update(path, b"final").await.unwrap();

    // 3. Seal (should coalesce to just "final")
    graph.flush().await.unwrap();
    let id_final = graph.get_id(path).await.unwrap();

    // 4. Verify that "final" points to "original", skipping the temp states
    let b_final = graph.store.get_block(&id_final).await.unwrap().unwrap();
    assert!(b_final.parents().contains(&id_orig));
    assert_eq!(b_final.parents().len(), 1);
}

#[tokio::test]
async fn flush_on_empty_staging_returns_nothing_to_flush() {
    let graph = create_test_graph().await;
    let result = graph.flush().await;
    assert!(matches!(result, Err(Error::NothingToFlush)));
}

#[tokio::test]
async fn flush_with_oversized_data_returns_block_size_exceeded() {
    let graph = create_test_graph().await;
    let path = "/test/large-file";
    let oversized = vec![0u8; graph.tuning.max_block_size + 1];

    graph.insert(path, oversized).await.unwrap();
    let result = graph.flush().await;

    match result {
        Err(Error::BlockSizeExceeded { path: p, size, max }) => {
            assert_eq!(p, path);
            assert!(size > max);
        }
        other => panic!("Expected BlockSizeExceeded, got {:?}", other),
    }
}

#[tokio::test]
async fn fetch_blob_returns_raw_bytes() {
    let graph = create_test_graph().await;
    let path = "/blob/data";
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

    graph.insert(path, data.clone()).await.unwrap();
    graph.flush().await.unwrap();

    let blob = graph.fetch_blob(path).await.unwrap();
    assert_eq!(blob, data);
}

#[tokio::test]
async fn fetch_blob_on_missing_path_returns_not_found() {
    let graph = create_test_graph().await;
    graph.insert("/doc", b"hello").await.unwrap();
    graph.flush().await.unwrap();

    let result = graph.fetch_blob("/missing/path").await;
    assert!(matches!(result, Err(Error::PathNotFound(_))));
}

#[tokio::test]
async fn insert_rejects_invalid_paths() {
    let graph = create_test_graph().await;

    // Missing leading slash
    let result = graph.insert("no-slash", b"data").await;
    assert!(
        matches!(result, Err(Error::InvalidPath { .. })),
        "Expected InvalidPath for missing leading slash"
    );

    // Empty path
    let result = graph.insert("", b"data").await;
    assert!(
        matches!(result, Err(Error::InvalidPath { .. })),
        "Expected InvalidPath for empty path"
    );

    // Null byte
    let result = graph.insert("/test/null\0byte", b"data").await;
    assert!(
        matches!(result, Err(Error::InvalidPath { .. })),
        "Expected InvalidPath for null byte"
    );
}

#[tokio::test]
async fn test_path_validation_split() {
    // Writes (validate_path) should reject .akshara. reserved segments
    assert!(validate_path("/test/doc").is_ok());
    assert!(validate_path("/test/.akshara.document").is_err());
    assert!(validate_path("").is_err());
    assert!(validate_path("no-slash").is_err());
    assert!(validate_path("/test/null\0byte").is_err());
    assert!(validate_path("/test/../sibling").is_err());

    // Reads (validate_path_read) should permit .akshara. reserved segments but reject other violations
    assert!(validate_path_read("/test/doc").is_ok());
    assert!(validate_path_read("/test/.akshara.document").is_ok());
    assert!(validate_path_read("").is_err());
    assert!(validate_path_read("no-slash").is_err());
    assert!(validate_path_read("/test/null\0byte").is_err());
    assert!(validate_path_read("/test/../sibling").is_err());
}
