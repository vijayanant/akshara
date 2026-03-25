use crate::base::address::{Address, BlockId, GraphId};
use crate::base::crypto::{AksharaSigner, GraphKey};
use crate::graph::Block;
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use sha2::Digest;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_merkle_index_path_resolution() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // 1. Create a data block
    let data_block = Block::new(
        graph_id,
        b"hello".to_vec(),
        crate::graph::BlockType::AksharaDataV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    // 2. Use IndexBuilder to construct an index block pointing to it
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("/title", Address::from(data_block.id()))
        .unwrap();
    let index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    // 3. Resolve path
    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved_addr = walker
        .resolve_path(&graph_id, index_id, "/title", &key)
        .await
        .unwrap();

    assert_eq!(resolved_addr, Address::from(data_block.id()));
}

#[tokio::test]
async fn test_merkle_index_nested_resolution() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Leaf
    let data_block = Block::new(
        graph_id,
        b"data".to_vec(),
        crate::graph::BlockType::AksharaDataV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    // Nested Hierarchy
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("nested/file", Address::from(data_block.id()))
        .unwrap();
    let root_index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved = walker
        .resolve_path(&graph_id, root_index_id, "nested/file", &key)
        .await
        .unwrap();

    assert_eq!(resolved, Address::from(data_block.id()));
}

#[tokio::test]
async fn test_merkle_index_path_normalization() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    let data_block = Block::new(
        graph_id,
        b"data".to_vec(),
        crate::graph::BlockType::AksharaDataV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("file", Address::from(data_block.id()))
        .unwrap();
    let root_index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    // All these should resolve correctly
    for path in ["file", "/file", "file/", "//file///"] {
        let resolved = walker
            .resolve_path(&graph_id, root_index_id, path, &key)
            .await
            .unwrap();
        assert_eq!(resolved, Address::from(data_block.id()));
    }
}

#[tokio::test]
async fn test_merkle_index_missing_path_failures() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("exists", Address::from(BlockId::from_sha256(&[1u8; 32])))
        .unwrap();
    let root_index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    assert!(
        walker
            .resolve_path(&graph_id, root_index_id, "does_not_exist", &key)
            .await
            .is_err()
    );
    assert!(
        walker
            .resolve_path(&graph_id, root_index_id, "exists/but_im_not_a_folder", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_wrong_key_failure() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let wrong_key = GraphKey::generate(&mut rng);

    let index_block = Block::new(
        graph_id,
        vec![1, 2, 3],
        crate::graph::BlockType::AksharaIndexV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&index_block).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    assert!(
        walker
            .resolve_path(&graph_id, index_block.id(), "any", &wrong_key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_malformed_cbor_failure() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Data block that IS NOT an index (not CBOR map)
    let data_block = Block::new(
        graph_id,
        b"not-cbor".to_vec(),
        crate::graph::BlockType::AksharaDataV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("not_a_folder", Address::from(data_block.id()))
        .unwrap();
    let root_index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    // Resolve first segment should work, but then it should fail to parse data_block as index
    assert!(
        walker
            .resolve_path(&graph_id, root_index_id, "not_a_folder/something", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_type_mismatch_failure() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // We promise a block but give it a manifest-formatted address (manual creation for test)
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            "fake",
            Address::from(crate::ManifestId::from_sha256(&[1u8; 32])),
        )
        .unwrap();
    let root_index_id = builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    // Should fail when trying to fetch "fake" as a BlockId
    assert!(
        walker
            .resolve_path(&graph_id, root_index_id, "fake/any", &key)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_merkle_index_circular_reference_protection() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // To test cycle detection, we need an index that points to itself.
    let loop_id = BlockId::from_sha256(&[0x69; 32]);

    let mut builder = crate::traversal::IndexBuilder::new();
    builder.insert("loop", Address::from(loop_id)).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("loop".to_string(), Address::from(loop_id));

    let content_bytes = crate::base::encoding::to_canonical_bytes(&root_map).unwrap();
    let nonce = [0u8; 24]; // Use 24-byte nonce for XChaCha20

    // We compute the required AD for the circular test
    let ad = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"AKSHARA_V1_AD");
        hasher.update(_graph_id.as_bytes());
        hasher.update(identity.public().signing_key().as_bytes());
        hasher.update(crate::graph::BlockType::AksharaIndexV1.as_str().as_bytes());
        // No parents in this test mock
        hasher.finalize().to_vec()
    };

    let content =
        crate::base::crypto::BlockContent::encrypt(&content_bytes, &key, nonce, &ad).unwrap();

    // We use from_raw_parts to FORCE the block into the store with the target ID.
    let root_index = Block::from_raw_parts(
        loop_id,
        identity.public().signing_key().clone(),
        identity.sign(loop_id.as_ref()),
        content,
        crate::graph::BlockType::AksharaIndexV1,
        vec![],
    );
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());

    // This should now fetch the block, and the Auditor will immediately catch
    // that the content hash doesn't match the loop_id we forced.
    let result = walker
        .resolve_path(&_graph_id, loop_id, "loop/loop", &key)
        .await;

    match result {
        Err(crate::AksharaError::Integrity(crate::IntegrityError::BlockIdMismatch(_))) => (),
        _ => panic!("Expected IntegrityError::BlockIdMismatch, got {:?}", result),
    }
}
