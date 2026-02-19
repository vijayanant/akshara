use crate::base::address::{Address, BlockId, GraphId};
use crate::base::crypto::{GraphKey, SovereignSigner};
use crate::graph::Block;
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

#[test]
fn test_merkle_index_path_resolution() {
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
    store.put_block(&data_block).unwrap();

    // 2. Create an index block pointing to it
    let mut index_map = BTreeMap::new();
    index_map.insert("title".to_string(), Address::from(data_block.id()));
    let index_block = Block::new(
        serde_cbor::to_vec(&index_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&index_block).unwrap();

    // 3. Resolve path
    let walker = GraphWalker::new(&store);
    let resolved_addr = walker
        .resolve_path(index_block.id(), "/title", &key)
        .unwrap();

    assert_eq!(resolved_addr, Address::from(data_block.id()));
}

#[test]
fn test_merkle_index_nested_resolution() {
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
    store.put_block(&data_block).unwrap();

    // Nested Index
    let mut nested_map = BTreeMap::new();
    nested_map.insert("file".to_string(), Address::from(data_block.id()));
    let nested_index = Block::new(
        serde_cbor::to_vec(&nested_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&nested_index).unwrap();

    // Root Index
    let mut root_map = BTreeMap::new();
    root_map.insert("nested".to_string(), Address::from(nested_index.id()));
    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    let resolved = walker
        .resolve_path(root_index.id(), "nested/file", &key)
        .unwrap();

    assert_eq!(resolved, Address::from(data_block.id()));
}

#[test]
fn test_merkle_index_path_normalization() {
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
    store.put_block(&data_block).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("file".to_string(), Address::from(data_block.id()));
    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // All these should resolve correctly
    for path in ["file", "/file", "file/", "//file///"] {
        let resolved = walker.resolve_path(root_index.id(), path, &key).unwrap();
        assert_eq!(resolved, Address::from(data_block.id()));
    }
}

#[test]
fn test_merkle_index_missing_path_failures() {
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
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    assert!(
        walker
            .resolve_path(root_index.id(), "does_not_exist", &key)
            .is_err()
    );
    assert!(
        walker
            .resolve_path(root_index.id(), "exists/but_im_not_a_folder", &key)
            .is_err()
    );
}

#[test]
fn test_merkle_index_wrong_key_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let wrong_key = GraphKey::generate(&mut rng);

    let index_block =
        Block::new(vec![1, 2, 3], "index".to_string(), vec![], &key, &identity).unwrap();
    store.put_block(&index_block).unwrap();

    let walker = GraphWalker::new(&store);
    assert!(
        walker
            .resolve_path(index_block.id(), "any", &wrong_key)
            .is_err()
    );
}

#[test]
fn test_merkle_index_malformed_cbor_failure() {
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
    store.put_block(&data_block).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("not_a_folder".to_string(), Address::from(data_block.id()));
    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    // Resolve first segment should work, but then it should fail to parse data_block as index
    assert!(
        walker
            .resolve_path(root_index.id(), "not_a_folder/something", &key)
            .is_err()
    );
}

#[test]
fn test_merkle_index_type_mismatch_failure() {
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
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    // Should fail when trying to fetch "fake" as a BlockId
    assert!(
        walker
            .resolve_path(root_index.id(), "fake/any", &key)
            .is_err()
    );
}

#[test]

fn test_merkle_index_circular_reference_protection() {
    let mut rng = OsRng;

    let mut store = InMemoryStore::new();

    let identity = SecretIdentity::generate(&mut rng);

    let _graph_id = GraphId::new();

    let key = GraphKey::generate(&mut rng);

    // To test cycle detection, we need an index that points to itself.

    // 1. We pre-calculate a deterministic ID.

    let loop_id = BlockId::from_sha256(&[0x69; 32]);

    // 2. We create an index block where "loop" points back to loop_id.

    let mut root_map = BTreeMap::new();

    root_map.insert("loop".to_string(), Address::from(loop_id));

    let content_bytes = serde_cbor::to_vec(&root_map).unwrap();

    let nonce = [0u8; 12];

    let content = crate::base::crypto::BlockContent::encrypt(&content_bytes, &key, nonce).unwrap();

    // 3. We use from_raw_parts to FORCE the block into the store with the target ID.

    // This simulates a malicious or corrupted graph.

    let root_index = Block::from_raw_parts(
        loop_id,
        identity.public().signing_key().clone(),
        identity.sign(loop_id.as_ref()),
        content,
        "index".to_string(),
        vec![],
    );

    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // This should now successfully fetch the block, see the pointer to itself,

    // fetch it AGAIN, and trigger the Cycle Detection invariant.

    let result = walker.resolve_path(loop_id, "loop/loop", &key);

    match result {
        Err(crate::SovereignError::Integrity(crate::IntegrityError::CycleDetected(addr))) => {
            assert_eq!(addr, Address::from(loop_id));
        }

        _ => panic!("Expected IntegrityError::CycleDetected, got {:?}", result),
    }
}
