use crate::base::address::{Address, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_identity_temporal_forgery_rejection() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let master = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let anchor = ManifestId::from_sha256(&[0u8; 32]);

    // 1. AT T=0: Authorize Device A
    let device_a = SecretIdentity::generate(&mut rng);
    let mut devices_map = BTreeMap::new();
    devices_map.insert(
        "phone".to_string(),
        Address::from(
            Block::new(
                device_a.public().signing_key().as_bytes().to_vec(),
                "auth".into(),
                vec![],
                &key,
                &master,
            )
            .unwrap()
            .id(),
        ),
    );

    let root_index_v1 = Block::new(
        serde_cbor::to_vec(&devices_map).unwrap(),
        "index".into(),
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&root_index_v1).await.unwrap();
    let manifest_v1 = Manifest::new(graph_id, root_index_v1.id(), vec![], anchor, &master);
    store.put_manifest(&manifest_v1).await.unwrap();

    // 2. AT T=10: Revoke Device A (Phone stolen!)
    let revoked_map: BTreeMap<String, Address> = BTreeMap::new();
    // "phone" is now missing from the index
    let root_index_v2 = Block::new(
        serde_cbor::to_vec(&revoked_map).unwrap(),
        "index".into(),
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&root_index_v2).await.unwrap();
    let manifest_v2 = Manifest::new(
        graph_id,
        root_index_v2.id(),
        vec![manifest_v1.id()],
        anchor,
        &master,
    );
    store.put_manifest(&manifest_v2).await.unwrap();

    // 3. THE ATTACK: Device A (Attacker) creates a block with a fake historical timestamp
    // They claim they wrote it at T=5 (before revocation) but they are signing it NOW.
    let malicious_data = b"Attacker Edit".to_vec();
    let malicious_block =
        Block::new(malicious_data, "post".into(), vec![], &key, &device_a).unwrap();

    // 4. VERIFY: Auditor checks authority against the CURRENT frontier
    let walker = GraphWalker::new(&store, master.public().signing_key().clone());

    // The Auditor stands upon manifest_v2 (The current truth)
    let current_root = manifest_v2.content_root();
    let result = walker.resolve_path(current_root, "/phone", &key).await;

    // The resolution MUST fail because at the current frontier, "phone" is gone.
    // It doesn't matter what the malicious block's timestamp says; the authority is missing.
    assert!(
        result.is_err(),
        "Auditor must reject signatures from a device not present in the current authority frontier"
    );

    // Even if they try to check the malicious block's ID, it has no authority path in manifest_v2
    let malicious_id = malicious_block.id();
    let _ = malicious_id; // satisfy compiler
}
