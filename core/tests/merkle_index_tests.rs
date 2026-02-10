mod common;
use common::*;
use sovereign_core::graph::{Block, GraphId, Manifest, GraphWalker};
use sovereign_core::store::{GraphStore, InMemoryStore};
use std::collections::BTreeMap;

#[test]
fn test_merkle_index_path_resolution() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let key = create_dummy_key();
    let anchor = create_dummy_anchor();

    // 1. Create a Data Block (The Leaf)
    let content = b"Secret Project".to_vec();
    let data_block = Block::new(content, "p".to_string(), vec![], &key, &identity)
        .expect("Failed to create data block");
    store.put_block(&data_block).unwrap();

    // 2. Create an Index Block (The Branch)
    let mut index_map = BTreeMap::new();
    index_map.insert("title".to_string(), data_block.id().0);

    let index_block =
        Block::new_index(index_map, vec![], &key, &identity).expect("Failed to create index block");
    store.put_block(&index_block).unwrap();

    // 3. Create a Manifest pointing to the index root
    let manifest = Manifest::new(
        graph_id,
        index_block.id(), // content_root
        vec![],           // parents
        anchor,
        &identity,
    );
    store.put_manifest(&manifest).unwrap();

        // 4. Resolve Path

        use sovereign_core::graph::GraphWalker;

        let walker = GraphWalker::new(&store);

        

        let resolved_cid = walker.resolve_path(manifest.content_root(), "title", &key).unwrap();

        assert_eq!(resolved_cid, data_block.id().0);

    }

    

    #[test]

    fn test_merkle_index_nested_resolution() {

        let mut store = InMemoryStore::new();

        let identity = create_identity();

        let key = create_dummy_key();

    

        // 1. Leaf: /nested/file -> "data"

        let data_block = Block::new(b"nested_data".to_vec(), "p".to_string(), vec![], &key, &identity).unwrap();

        store.put_block(&data_block).unwrap();

    

        // 2. Index: /nested -> { "file": data_block_id }

        let mut nested_map = BTreeMap::new();

        nested_map.insert("file".to_string(), data_block.id().0);

        let nested_index = Block::new_index(nested_map, vec![], &key, &identity).unwrap();

        store.put_block(&nested_index).unwrap();

    

        // 3. Root Index: / -> { "nested": nested_index_id }

        let mut root_map = BTreeMap::new();

        root_map.insert("nested".to_string(), nested_index.id().0);

        let root_index = Block::new_index(root_map, vec![], &key, &identity).unwrap();

        store.put_block(&root_index).unwrap();

    

        // 4. Resolve: "nested/file"

        let walker = GraphWalker::new(&store);

        let resolved = walker.resolve_path(root_index.id(), "nested/file", &key).unwrap();

        

        assert_eq!(resolved, data_block.id().0);

    }

    
