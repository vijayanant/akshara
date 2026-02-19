use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::auditor::Auditor;
use crate::traversal::create_valid_anchor;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// **TEST: Imposter Genesis Hijack (Negative)**
///
/// This test verifies that the system rejects a "New Universe" attack.
/// An attacker (Eve) tries to create a new genesis manifest (anchor: 0) for Alice's
/// document. Even if the signature is mathematically correct (Eve signed it),
/// the Auditor must reject it because the signer is not Alice's Master Root Key.
#[test]
fn test_negative_imposter_genesis_hijack() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();

    // Alice is the legitimate owner defined in the Auditor's context
    let alice = SecretIdentity::generate(&mut rng);
    let master_key = alice.public().signing_key().clone();

    // Eve is the attacker
    let eve = SecretIdentity::generate(&mut rng);

    // Eve creates a manifest claiming to be a Genesis (anchor: 0) for Alice's document
    let graph_id = GraphId::new();
    let root = BlockId::from_sha256(&[0xFF; 32]);
    let null_anchor = ManifestId::from_sha256(&[0x00; 32]);

    let imposter_manifest = Manifest::new(
        graph_id,
        root,
        vec![],
        null_anchor,
        &eve, // Signed by Eve!
    );

    // The Auditor is initialized expecting Alice to be the root of trust
    let auditor = Auditor::new(&store, master_key);

    // Audit must fail because the genesis manifest isn't signed by the master key
    let result = auditor.audit_manifest(&imposter_manifest);
    assert!(
        result.is_err(),
        "Auditor should have rejected genesis manifest not signed by master key"
    );
}

/// **TEST: Identity Graph Swap (Negative)**
///
/// This test verifies that a signer cannot "borrow" someone else's authority.
/// Bob signs a manifest but points the `identity_anchor` to Alice's identity graph.
/// Since Bob is not an authorized device in Alice's graph, the walk will fail
/// to find his public key, and the manifest must be rejected.
#[test]
fn test_negative_identity_graph_swap() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();

    let alice = SecretIdentity::generate(&mut rng);
    let bob = SecretIdentity::generate(&mut rng);

    // 1. Setup Alice's real anchor (Alice is authorized in her own graph)
    let alice_anchor = create_valid_anchor(&mut store, &alice);

    // 2. Bob tries to sign a manifest but points to ALICE'S identity graph
    let graph_id = GraphId::new();
    let root = BlockId::from_sha256(&[0xEE; 32]);

    let forged_manifest = Manifest::new(
        graph_id,
        root,
        vec![],
        alice_anchor,
        &bob, // Bob signs, but uses Alice's history
    );

    // The Auditor expects Alice's root
    let auditor = Auditor::new(&store, alice.public().signing_key().clone());

    // Audit must fail because Bob is not authorized in Alice's history
    let result = auditor.audit_manifest(&forged_manifest);
    assert!(
        result.is_err(),
        "Auditor should have rejected Bob signing with Alice's anchor"
    );
}

/// **TEST: Stale Authority / Temporal Forgery (Negative)**
///
/// This test verifies that authority is CAUSAL.
/// 1. Genesis state exists (Master Key only).
/// 2. Device A is added in a later snapshot (Snapshot #2).
/// 3. Device A tries to sign a manifest anchored to the Genesis state.
///
/// This must fail because at the Genesis point, Device A did not yet exist
/// in the authorized device list. Signers cannot reach back in time to
/// exercise authority they didn't have yet.
#[test]
fn test_negative_identity_stale_authority() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let alice = SecretIdentity::generate(&mut rng);
    let master_key = alice.public().signing_key().clone();

    // 1. Genesis State (Master Key only)
    let genesis_anchor = create_valid_anchor(&mut store, &alice);

    // 2. Device A is added in a NEW identity snapshot
    let device_a = SecretIdentity::generate(&mut rng);
    let identity_key = GraphKey::new([0u8; 32]);
    let mut devices_map = BTreeMap::new();

    // Master Key (from genesis) + Device A
    let auth_master = Block::new(vec![], "auth".into(), vec![], &identity_key, &alice).unwrap();
    let auth_device_a = Block::new(vec![], "auth".into(), vec![], &identity_key, &alice).unwrap();
    store.put_block(&auth_master).unwrap();
    store.put_block(&auth_device_a).unwrap();

    // Manual hex encoding for test setup
    let master_hex = master_key
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let device_a_hex = device_a
        .public()
        .signing_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    devices_map.insert(master_hex, Address::from(auth_master.id()));
    devices_map.insert(device_a_hex, Address::from(auth_device_a.id()));

    let mut devices_index_map = BTreeMap::new();
    let devices_index = Block::new(
        serde_cbor::to_vec(&devices_map).unwrap(),
        "index".into(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&devices_index).unwrap();
    devices_index_map.insert("devices".to_string(), Address::from(devices_index.id()));

    let root_index = Block::new(
        serde_cbor::to_vec(&devices_index_map).unwrap(),
        "index".into(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&root_index).unwrap();

    let _snapshot_2 = Manifest::new(
        GraphId::new(),
        root_index.id(),
        vec![genesis_anchor],
        genesis_anchor,
        &alice,
    );
    // (We don't even need to store snapshot_2 for this test, because we are testing Device A anchoring to genesis_anchor)

    // 3. ATTACK: Device A tries to sign a manifest anchored to the GENESIS snapshot
    // (Before it was authorized!)
    let stale_manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[0x11; 32]),
        vec![],
        genesis_anchor,
        &device_a,
    );

    let auditor = Auditor::new(&store, master_key);
    let result = auditor.audit_manifest(&stale_manifest);

    assert!(
        result.is_err(),
        "Auditor should reject signatures anchored to snapshots before authorization"
    );
}
