use std::collections::BTreeMap;

use rand::rngs::OsRng;

use crate::{
    BlockId, GraphId, GraphKey, ManifestId,
    graph::{Block, Manifest},
    identity::SecretIdentity,
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::walker::GraphWalker,
};

// Helper functions

#[allow(dead_code)]
pub fn create_dummy_key() -> GraphKey {
    GraphKey::generate(&mut OsRng)
}

#[allow(dead_code)]
pub fn create_dummy_anchor() -> ManifestId {
    ManifestId::from_sha256(&[0u8; 32])
}

#[test]
fn test_sovereign_blind_discovery_derivation() {
    let mut rng = rand::thread_rng();
    let id_a = SecretIdentity::generate(&mut rng);
    let id_b = SecretIdentity::generate(&mut rng);

    // Using the clean Sovereign API
    let disco_a1 = id_a.derive_discovery_id();
    let disco_a2 = id_a.derive_discovery_id();
    let disco_b = id_b.derive_discovery_id();

    assert_eq!(disco_a1, disco_a2, "Discovery ID must be deterministic");
    assert_ne!(disco_a1, disco_b, "Discovery ID must be unique per user");
}

#[test]
fn test_sovereign_full_authority_chain_verification() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    // 1. TIER 1: Master Root
    let master = SecretIdentity::generate(&mut rng);
    let master_key = create_dummy_key();

    // 2. TIER 2: Device Key (Delegated Active Signer)
    let laptop = SecretIdentity::generate(&mut rng);
    let laptop_pub_key = laptop.public().signing_key().clone();

    // 3. Alice publishes her Identity Graph
    // Path: /devices/laptop -> laptop_pub_key
    let device_block = Block::new(
        laptop_pub_key.as_bytes().to_vec(),
        "key".to_string(),
        vec![],
        &master_key,
        &master,
    )
    .unwrap();
    store.put_block(&device_block).unwrap();

    let mut devices_map = BTreeMap::new();
    devices_map.insert("laptop".to_string(), device_block.id().0);
    let devices_index = Block::new_index(devices_map, vec![], &master_key, &master).unwrap();
    store.put_block(&devices_index).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("devices".to_string(), devices_index.id().0);
    let root_index = Block::new_index(root_map, vec![], &master_key, &master).unwrap();
    store.put_block(&root_index).unwrap();

    let identity_manifest = Manifest::new(
        GraphId::new(),
        root_index.id(),
        vec![],
        create_dummy_anchor(),
        &master,
    );
    store.put_manifest(&identity_manifest).unwrap();

    // 4. SCENARIO: The Laptop signs a contract
    let contract_key = create_dummy_key();
    let contract_block = Block::new(
        b"I agree to terms".to_vec(),
        "contract".to_string(),
        vec![],
        &contract_key,
        &laptop,
    )
    .unwrap();

    // 5. THE VERTICAL PROOF: Bob verifies Alice's authority
    let signer_key = contract_block.author();

    let walker = GraphWalker::new(&store);
    let resolved_cid = walker
        .resolve_path(
            identity_manifest.content_root(),
            "devices/laptop",
            &master_key,
        )
        .expect("Identity resolution failed");

    let key_block = store.get_block(&BlockId(resolved_cid)).unwrap().unwrap();
    let decrypted_key_bytes = key_block.content().decrypt(&master_key).unwrap();

    assert_eq!(
        decrypted_key_bytes,
        signer_key.as_bytes().to_vec(),
        "Signer must match Identity Graph"
    );
    assert_eq!(
        identity_manifest.author(),
        master.public().signing_key(),
        "Identity Graph must match Master"
    );
}
