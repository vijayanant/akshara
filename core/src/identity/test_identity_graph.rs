use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::{create_dummy_anchor, create_dummy_key};
use crate::{Block, BlockId, GraphId, GraphWalker, Manifest};
use std::collections::BTreeMap;

#[test]
fn test_identity_graph_device_resolution() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    // 1. Tier 1: Master Identity (The Authority)
    let master_identity = SecretIdentity::generate(&mut rng);
    let master_key = create_dummy_key();

    // 2. Tier 2: The Device (e.g. this laptop)
    let device_identity = SecretIdentity::generate(&mut rng);
    let device_pub_key = device_identity.public().signing_key().as_bytes();

    // 3. Build the Identity Graph Structure
    let device_block = Block::new(
        device_pub_key.to_vec(),
        "key".to_string(),
        vec![],
        &master_key,
        &master_identity,
    )
    .expect("Failed to create device block");
    store.put_block(&device_block).unwrap();

    let mut devices_map = BTreeMap::new();
    devices_map.insert("laptop_1".to_string(), *device_block.id().as_cid());

    let devices_index = Block::new_index(devices_map, vec![], &master_key, &master_identity)
        .expect("Failed to create devices index");
    store.put_block(&devices_index).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("devices".to_string(), *devices_index.id().as_cid());
    let root_index = Block::new_index(root_map, vec![], &master_key, &master_identity)
        .expect("Failed to create identity root index");
    store.put_block(&root_index).unwrap();

    // 4. Create the Identity Manifest
    let graph_id = GraphId::new();
    let anchor = create_dummy_anchor();
    let manifest = Manifest::new(graph_id, root_index.id(), vec![], anchor, &master_identity);
    store.put_manifest(&manifest).unwrap();

    // 5. Verify: Resolve Device Key via the Identity Graph
    let walker = GraphWalker::new(&store);
    let resolved_cid = walker
        .resolve_path(manifest.content_root(), "devices/laptop_1", &master_key)
        .expect("Failed to resolve device path");

    let resolved_block = store
        .get_block(&BlockId::from_cid(resolved_cid))
        .unwrap()
        .unwrap();
    let decrypted_payload = resolved_block.content().decrypt(&master_key).unwrap();

    assert_eq!(&decrypted_payload, device_pub_key);
}

#[test]
fn test_identity_graph_missing_device_failure() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    let master_identity = SecretIdentity::generate(&mut rng);
    let master_key = create_dummy_key();

    // 1. Create empty devices index
    let devices_map = BTreeMap::new();
    let devices_index =
        Block::new_index(devices_map, vec![], &master_key, &master_identity).unwrap();
    store.put_block(&devices_index).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("devices".to_string(), *devices_index.id().as_cid());
    let root_index = Block::new_index(root_map, vec![], &master_key, &master_identity).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // 2. Resolve non-existent device
    let result = walker.resolve_path(root_index.id(), "devices/phone_1", &master_key);
    assert!(
        result.is_err(),
        "Resolution must fail if device path is missing"
    );
}

#[test]
fn test_identity_graph_unauthorized_traversal_failure() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    let alice = SecretIdentity::generate(&mut rng);
    let alice_key = create_dummy_key();
    let eve_key = create_dummy_key();

    let root_index = Block::new_index(BTreeMap::new(), vec![], &alice_key, &alice).unwrap();
    store.put_block(&root_index).unwrap();

    let walker = GraphWalker::new(&store);

    // 3. Attempt resolution with WRONG key
    let result = walker.resolve_path(root_index.id(), "anything", &eve_key);
    assert!(
        result.is_err(),
        "Must fail when trying to traverse identity graph with unauthorized key"
    );
}
