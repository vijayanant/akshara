use crate::traversal::{create_dummy_anchor, create_dummy_key, create_identity};
use crate::{Block, GraphId, GraphStore, GraphWalker, InMemoryStore, Manifest};
use std::collections::BTreeMap;

#[test]
fn test_merkle_index_path_resolution() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let key = create_dummy_key();
    let anchor = create_dummy_anchor();

    let content = b"Secret Project".to_vec();
    let data_block = Block::new(content, "p".to_string(), vec![], &key, &identity).unwrap();
    store.put_block(&data_block).unwrap();

    let mut index_map = BTreeMap::new();
    index_map.insert("title".to_string(), *data_block.id().as_cid());
    let index_block = Block::new_index(index_map, vec![], &key, &identity).unwrap();
    store.put_block(&index_block).unwrap();

    let manifest = Manifest::new(graph_id, index_block.id(), vec![], anchor, &identity);
    store.put_manifest(&manifest).unwrap();

    let walker = GraphWalker::new(&store);
    let resolved_cid = walker
        .resolve_path(manifest.content_root(), "title", &key)
        .unwrap();
    assert_eq!(resolved_cid, *data_block.id().as_cid());
}

#[test]
fn test_merkle_index_nested_resolution() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    let data_block = Block::new(
        b"nested_data".to_vec(),
        "p".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).unwrap();

    let mut nested_map = BTreeMap::new();
    nested_map.insert("file".to_string(), *data_block.id().as_cid());
    let nested_index = Block::new_index(nested_map, vec![], &key, &identity).unwrap();
    store.put_block(&nested_index).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("nested".to_string(), *nested_index.id().as_cid());
    let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    let resolved = walker
        .resolve_path(root_index.id(), "nested/file", &key)
        .unwrap();
    assert_eq!(resolved, *data_block.id().as_cid());
}

#[test]
fn test_merkle_index_path_normalization() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    let data_block =
        Block::new(b"data".to_vec(), "p".to_string(), vec![], &key, &identity).unwrap();
    store.put_block(&data_block).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("file".to_string(), *data_block.id().as_cid());
    let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    let cases = vec!["file", "/file", "file/", "//file//"];
    for case in cases {
        let resolved = walker
            .resolve_path(root_index.id(), case, &key)
            .unwrap_or_else(|_| panic!("Failed on case: {}", case));
        assert_eq!(resolved, *data_block.id().as_cid());
    }
}

#[test]
fn test_merkle_index_missing_path_failures() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    let mut root_map = BTreeMap::new();
    root_map.insert(
        "exists_in_index_but_missing_in_store".to_string(),
        *crate::BlockId::from_sha256(&[1u8; 32]).as_cid(),
    );
    let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // 1. Non-existent segment
    let result = walker.resolve_path(root_index.id(), "ghost", &key);
    assert!(
        result.is_err(),
        "Should fail for non-existent segment 'ghost'"
    );

    // 2. Missing block in store (THE FIX)
    let result = walker.resolve_path(
        root_index.id(),
        "exists_in_index_but_missing_in_store",
        &key,
    );
    assert!(
        result.is_err(),
        "Should fail if the resolved leaf is missing from store"
    );
}

#[test]
fn test_merkle_index_type_mismatch_failure() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    // Create a DATA block
    let data_block = Block::new(
        b"I am data".to_vec(),
        "p".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&data_block).unwrap();

    // Root index points to the data block
    let mut root_map = BTreeMap::new();
    root_map.insert("not_a_folder".to_string(), *data_block.id().as_cid());
    let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // Try to resolve THROUGH the data block
    let result = walker.resolve_path(root_index.id(), "not_a_folder/file", &key);
    assert!(
        result.is_err(),
        "Should fail when trying to walk through a non-index block"
    );
}

#[test]
fn test_merkle_index_wrong_key_failure() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key_correct = create_dummy_key();
    let key_wrong = create_dummy_key();

    let mut root_map = BTreeMap::new();
    root_map.insert(
        "file".to_string(),
        *crate::BlockId::from_sha256(&[1u8; 32]).as_cid(),
    );
    let root_index = Block::new_index(root_map, vec![], &key_correct, &identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);
    let result = walker.resolve_path(root_index.id(), "file", &key_wrong);
    assert!(result.is_err(), "Resolution must fail with wrong key");
}

#[test]
fn test_merkle_index_circular_reference_protection() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    let self_pointing_cid = crate::BlockId::from_sha256(&[0xCC; 32]);

    let mut root_map = BTreeMap::new();
    root_map.insert("loop".to_string(), *self_pointing_cid.as_cid());

    let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();
    let root_index = Block::from_raw_parts(
        self_pointing_cid,
        root_index.author().clone(),
        root_index.signature().clone(),
        root_index.content().clone(),
        root_index.block_type().to_string(),
        vec![],
    );
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    let result = walker.resolve_path(root_index.id(), "loop/loop/loop", &key);
    assert!(result.is_err());
}

#[test]
fn test_merkle_index_malformed_cbor_failure() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let key = create_dummy_key();

    let junk_data = vec![0xFF, 0xFE, 0xFD];
    let block = Block::new(junk_data, "index".to_string(), vec![], &key, &identity).unwrap();
    store.put_block(&block).unwrap();

    let walker = GraphWalker::new(&store);
    let result = walker.resolve_path(block.id(), "anything", &key);

    assert!(result.is_err(), "Should fail when CBOR is malformed");
}
