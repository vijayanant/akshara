use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, BlockType, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;

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
        crate::base::encoding::to_canonical_bytes(&"my-iphone".to_string()).unwrap(),
        BlockType::AksharaDataV1,
        vec![],
        &key,
        &device_identity,
    )
    .unwrap();
    store.put_block(&device_block).await.unwrap();

    // 2. Use IndexBuilder to construct the Identity Graph hierarchy
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("credentials/laptop_1", Address::from(device_block.id()))
        .unwrap();
    let root_index_id = builder.build(&mut store, &identity, &key).await.unwrap();

    // 4. Create Identity Manifest
    let anchor = ManifestId::null();
    let manifest = crate::graph::Manifest::new(graph_id, root_index_id, vec![], anchor, &identity);
    store.put_manifest(&manifest).await.unwrap();

    // 5. Walk the Identity Graph
    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let resolved_addr = walker
        .resolve_path(root_index_id, "/credentials/laptop_1", &key)
        .await
        .unwrap();

    let resolved_block_id = BlockId::try_from(resolved_addr).unwrap();
    let block = store
        .get_block(&resolved_block_id)
        .await
        .unwrap()
        .expect("Block not found");

    let name: String =
        crate::base::encoding::from_canonical_bytes(&block.content().decrypt(&key).unwrap())
            .unwrap();
    assert_eq!(name, "my-iphone");
}

#[tokio::test]
async fn test_identity_graph_missing_device_failure() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rng);
    let _graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // Use IndexBuilder to construct an index with a different path
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            "credentials/other_device",
            Address::from(BlockId::from_sha256(&[1u8; 32])),
        )
        .unwrap();
    let root_index_id = builder.build(&mut store, &identity, &key).await.unwrap();

    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let result = walker
        .resolve_path(root_index_id, "/credentials/stolen_laptop", &key)
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
    let anchor = ManifestId::null();

    // 1. Initial State: Device A is authorized
    let device_a = SecretIdentity::generate(&mut rng);
    let device_a_block = Block::new(
        device_a.public().signing_key().as_bytes().to_vec(),
        "akshara.auth.v1".into(),
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&device_a_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert("phone", Address::from(device_a_block.id()))
        .unwrap();

    let root_index_id = builder.build(&mut store, &master, &key).await.unwrap();

    let manifest = Manifest::new(graph_id, root_index_id, vec![], anchor, &master);
    store.put_manifest(&manifest).await.unwrap();

    {
        let walker = GraphWalker::new(&store, master.public().signing_key().clone());
        let result = walker.resolve_path(root_index_id, "/phone", &key).await;

        // Initially must succeed
        assert!(
            result.is_ok(),
            "Initial resolution failed: {:?}",
            result.err()
        );
    }

    // 2. Revocation: phone is removed from the index
    let builder_v2 = crate::traversal::IndexBuilder::new();
    let root_index_v2 = builder_v2.build(&mut store, &master, &key).await.unwrap();

    {
        let walker = GraphWalker::new(&store, master.public().signing_key().clone());
        let result_v2 = walker.resolve_path(root_index_v2, "/phone", &key).await;

        // Must fail because the device is no longer in the graph
        assert!(result_v2.is_err());
    }
}
