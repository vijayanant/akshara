use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, BlockType, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

#[test]
fn test_sovereign_blind_discovery_derivation() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);

    // Derived ID for finding the Identity Graph on a Relay
    let discovery_id = identity.derive_discovery_id().expect("Derivation failed");

    // Must be stable
    let discovery_id_2 = identity.derive_discovery_id().expect("Derivation failed");
    assert_eq!(discovery_id, discovery_id_2);

    // Must be unique per identity
    let identity_2 = SecretIdentity::generate(&mut rng);
    assert_ne!(
        discovery_id,
        identity_2.derive_discovery_id().expect("Derivation failed")
    );
}

#[tokio::test]
async fn test_sovereign_full_authority_chain_verification() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();

    // 1. Setup Master Identity
    let master = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);

    // 2. Authorize a Device
    let device = SecretIdentity::generate(&mut rng);
    let device_block = Block::new(
        device.public().signing_key().as_bytes().to_vec(),
        BlockType::AksharaAuthV1,
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&device_block).await.unwrap();

    let mut devices_map = BTreeMap::new();
    devices_map.insert("laptop".to_string(), Address::from(device_block.id()));
    let devices_index = Block::new(
        crate::base::encoding::to_canonical_bytes(&devices_map).unwrap(),
        BlockType::AksharaIndexV1,
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&devices_index).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("credentials".to_string(), Address::from(devices_index.id()));
    let root_index = Block::new(
        crate::base::encoding::to_canonical_bytes(&root_map).unwrap(),
        BlockType::AksharaIndexV1,
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let anchor = ManifestId::from_sha256(&[0u8; 32]);
    let manifest = Manifest::new(graph_id, root_index.id(), vec![], anchor, &master);
    store.put_manifest(&manifest).await.unwrap();

    // 3. Device signs a document update
    let doc_root = BlockId::from_sha256(&[0xAA; 32]);
    let doc_manifest = Manifest::new(graph_id, doc_root, vec![], manifest.id(), &device);

    // 4. VERIFY: Auditor walks the identity graph to check authorization
    let walker = GraphWalker::new(&store, master.public().signing_key().clone());
    let resolved_addr = walker
        .resolve_path(root_index.id(), "/credentials/laptop", &key)
        .await
        .unwrap();

    let resolved_block_id = BlockId::try_from(resolved_addr).unwrap();
    let block = store
        .get_block(&resolved_block_id)
        .await
        .unwrap()
        .expect("Block not found");

    // Verify the resolved key matches the device that signed the document
    let authorized_key_bytes = block.content().decrypt(&key).unwrap();
    assert_eq!(
        authorized_key_bytes,
        device.public().signing_key().as_bytes()
    );

    // Final Proof: Reify the bytes into a real public key and verify the manifest signature
    let mut pub_key_bytes = [0u8; 32];
    pub_key_bytes.copy_from_slice(&authorized_key_bytes);
    let authorized_pub_key = crate::base::crypto::SigningPublicKey::new(pub_key_bytes);

    // Manifest::verify_integrity() internally uses the manifest's stored author key.
    // Here we prove that the resolved_pub_key is the same one used in the manifest.
    assert_eq!(authorized_pub_key, *doc_manifest.author());
    doc_manifest
        .verify_integrity()
        .expect("Manifest integrity failed");
}
