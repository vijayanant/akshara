use crate::base::address::{Address, BlockId, GraphId};
use crate::base::crypto::{GraphKey, SovereignSigner};
use crate::graph::Block;
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_merkle_index_path_resolution() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // 1. Create a data block
    let data_block = Block::new(
        b"hello".to_vec(),
        "data".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    // 2. Create an index block pointing to it
    let mut index_map = BTreeMap::new();
    index_map.insert("title".to_string(), Address::from(data_block.id()));
    let index_block = Block::new(
        serde_ipld_dagcbor::to_vec(&index_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&index_block).await.unwrap();

    // 3. Resolve path
    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved_addr = walker
        .resolve_path(index_block.id(), "/title", &key)
        .await
        .unwrap();

    assert_eq!(resolved_addr, Address::from(data_block.id()));
}

#[tokio::test]
async fn test_merkle_index_nested_resolution() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Leaf
    let data_block = Block::new(
        b"data".to_vec(),
        "data".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    // Nested Index
    let mut nested_map = BTreeMap::new();
    nested_map.insert("file".to_string(), Address::from(data_block.id()));
    let nested_index = Block::new(
        serde_ipld_dagcbor::to_vec(&nested_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&nested_index).await.unwrap();

    // Root Index
    let mut root_map = BTreeMap::new();
    root_map.insert("nested".to_string(), Address::from(nested_index.id()));
    let root_index = Block::new(
        serde_ipld_dagcbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved = walker
        .resolve_path(root_index.id(), "nested/file", &key)
        .await
        .unwrap();

    assert_eq!(resolved, Address::from(data_block.id()));
}

#[tokio::test]
async fn test_merkle_index_path_normalization() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    let data_block = Block::new(
        b"data".to_vec(),
        "data".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("file".to_string(), Address::from(data_block.id()));
    let root_index = Block::new(
        serde_ipld_dagcbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    // All these should resolve correctly
    for path in ["file", "/file", "file/", "//file///"] {
        let resolved = walker
            .resolve_path(root_index.id(), path, &key)
            .await
            .unwrap();
        assert_eq!(resolved, Address::from(data_block.id()));
    }
}

#[tokio::test]
async fn test_merkle_index_missing_path_failures() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    let mut root_map = BTreeMap::new();
    root_map.insert(
        "exists".to_string(),
        Address::from(BlockId::from_sha256(&[1u8; 32])),
    );
    let root_index = Block::new(
        serde_ipld_dagcbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    assert!(
        walker
            .resolve_path(root_index.id(), "does_not_exist", &key)
            .await
            .is_err()
    );
    assert!(
        walker
            .resolve_path(root_index.id(), "exists/but_im_not_a_folder", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_wrong_key_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let wrong_key = GraphKey::generate(&mut rng);

    let index_block = Block::new(
        vec![1, 2, 3],
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&index_block).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    assert!(
        walker
            .resolve_path(index_block.id(), "any", &wrong_key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_malformed_cbor_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Data block that IS NOT an index (not CBOR map)
    let data_block = Block::new(
        b"not-cbor".to_vec(),
        "data".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("not_a_folder".to_string(), Address::from(data_block.id()));
    let root_index = Block::new(
        serde_ipld_dagcbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    // Resolve first segment should work, but then it should fail to parse data_block as index
    assert!(
        walker
            .resolve_path(root_index.id(), "not_a_folder/something", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_type_mismatch_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // We promise a block but give it a manifest-formatted address (manual creation for test)
    let mut root_map = BTreeMap::new();
    root_map.insert(
        "fake".to_string(),
        Address::from(crate::ManifestId::from_sha256(&[1u8; 32])),
    );
    let root_index = Block::new(
        serde_ipld_dagcbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    // Should fail when trying to fetch "fake" as a BlockId
    assert!(
        walker
            .resolve_path(root_index.id(), "fake/any", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_circular_reference_protection() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // To test cycle detection, we need an index that points to itself.
    let loop_id = BlockId::from_sha256(&[0x69; 32]);

    let mut root_map = BTreeMap::new();
    root_map.insert("loop".to_string(), Address::from(loop_id));

    let content_bytes = serde_ipld_dagcbor::to_vec(&root_map).unwrap();
    let nonce = [0u8; 12];
    let content = crate::base::crypto::BlockContent::encrypt(&content_bytes, &key, nonce).unwrap();

    // We use from_raw_parts to FORCE the block into the store with the target ID.
    let root_index = Block::from_raw_parts(
        loop_id,
        identity.public().signing_key().clone(),
        identity.sign(loop_id.as_ref()),
        content,
        "akshara.index.v1".to_string(),
        vec![],
    );
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    // This should now fetch the block, and the Auditor will immediately catch
    // that the content hash doesn't match the loop_id we forced.
    let result = walker.resolve_path(loop_id, "loop/loop", &key).await;

    match result {
        Err(crate::SovereignError::Integrity(crate::IntegrityError::BlockIdMismatch(_))) => (),
        _ => panic!("Expected IntegrityError::BlockIdMismatch, got {:?}", result),
    }
}
