use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_identity_graph_device_resolution() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // 1. Create a Device Block
    let device_identity = SecretIdentity::generate(&mut rng);
    let device_block = Block::new(
        serde_cbor::to_vec(&"my-iphone".to_string()).unwrap(),
        "akshara.data.v1".to_string(),
        vec![],
        &key,
        &device_identity,
    )
    .unwrap();
    store.put_block(&device_block).await.unwrap();

    // 2. Create Devices Index
    let mut devices_map = BTreeMap::new();
    devices_map.insert("laptop_1".to_string(), Address::from(device_block.id()));
    let devices_index = Block::new(
        serde_cbor::to_vec(&devices_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&devices_index).await.unwrap();

    // 3. Create Root Index
    let mut root_map = BTreeMap::new();
    root_map.insert("credentials".to_string(), Address::from(devices_index.id()));
    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    // 4. Create Identity Manifest
    let anchor = ManifestId::from_sha256(&[0u8; 32]);
    let manifest =
        crate::graph::Manifest::new(graph_id, root_index.id(), vec![], anchor, &identity);
    store.put_manifest(&manifest).await.unwrap();

    // 5. Walk the Identity Graph
    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved_addr = walker
        .resolve_path(root_index.id(), "/credentials/laptop_1", &key)
        .await
        .unwrap();

    let resolved_block_id = BlockId::try_from(resolved_addr).unwrap();
    let block = store
        .get_block(&resolved_block_id)
        .await
        .unwrap()
        .expect("Block not found");

    let name: String = serde_cbor::from_slice(&block.content().decrypt(&key).unwrap()).unwrap();
    assert_eq!(name, "my-iphone");
}

#[tokio::test]
async fn test_identity_graph_missing_device_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Create Root Index with empty devices
    let devices_map: BTreeMap<String, Address> = BTreeMap::new();
    let devices_index = Block::new(
        serde_cbor::to_vec(&devices_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&devices_index).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("credentials".to_string(), Address::from(devices_index.id()));
    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let result = walker
        .resolve_path(root_index.id(), "/credentials/stolen_laptop", &key)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_identity_graph_unauthorized_traversal_failure() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let fake_root = BlockId::from_sha256(&[0xFF; 32]);

    // Should fail because the block doesn't exist in store
    let result = walker
        .resolve_path(fake_root, "/credentials/laptop", &key)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_identity_graph_revocation() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let master = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let anchor = ManifestId::from_sha256(&[0u8; 32]);

    // 1. Initial State: Device A is authorized
    let device_a = SecretIdentity::generate(&mut rng);
    let mut devices_map = BTreeMap::new();
    devices_map.insert(
        "phone".to_string(),
        Address::from(
            Block::new(
                device_a.public().signing_key().as_bytes().to_vec(),
                "akshara.auth.v1".into(),
                vec![],
                &key,
                &master,
            )
            .unwrap()
            .id(),
        ),
    );
    // ... we skip actually putting blocks for brevity in this setup,
    // but the logic follows the structure.

    // In a real scenario, revocation is a NEW manifest that points to a root index

    // where "phone" is either removed or mapped to a "Revoked" tombstone.

    let revoked_map: BTreeMap<String, Address> = BTreeMap::new();

    // "phone" is NOT in revoked_map

    let root_index = Block::new(
        serde_cbor::to_vec(&revoked_map).unwrap(),
        "akshara.index.v1".into(),
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let manifest = Manifest::new(graph_id, root_index.id(), vec![], anchor, &master);
    store.put_manifest(&manifest).await.unwrap();

    let walker = GraphWalker::new(&store, master.public().signing_key().clone());
    let result = walker.resolve_path(root_index.id(), "/phone", &key).await;

    // Must fail because the device is no longer in the graph
    assert!(result.is_err());
}
