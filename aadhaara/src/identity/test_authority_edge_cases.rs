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
#[tokio::test]
async fn test_negative_imposter_genesis_hijack() {
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
    let result = auditor.audit_manifest(&imposter_manifest).await;
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
#[tokio::test]
async fn test_negative_identity_graph_swap() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();

    let alice = SecretIdentity::generate(&mut rng);
    let bob = SecretIdentity::generate(&mut rng);

    // 1. Setup Alice's real anchor (Alice is authorized in her own graph)
    let alice_anchor = create_valid_anchor(&mut store, &alice).await;

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
    let result = auditor.audit_manifest(&forged_manifest).await;
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
#[tokio::test]
async fn test_negative_identity_stale_authority() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let alice = SecretIdentity::generate(&mut rng);
    let master_key = alice.public().signing_key().clone();

    // 1. Genesis State (Master Key only)
    let genesis_anchor = create_valid_anchor(&mut store, &alice).await;

    // 2. Device A is added in a NEW identity snapshot
    let device_a = SecretIdentity::generate(&mut rng);
    let identity_key = GraphKey::new([0u8; 32]);
    let mut devices_map = BTreeMap::new();

    // Master Key (from genesis) + Device A
    let auth_master = Block::new(vec![], "auth".into(), vec![], &identity_key, &alice).unwrap();
    let auth_device_a = Block::new(vec![], "auth".into(), vec![], &identity_key, &alice).unwrap();
    store.put_block(&auth_master).await.unwrap();
    store.put_block(&auth_device_a).await.unwrap();

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
    store.put_block(&devices_index).await.unwrap();
    devices_index_map.insert("devices".to_string(), Address::from(devices_index.id()));

    let root_index = Block::new(
        serde_cbor::to_vec(&devices_index_map).unwrap(),
        "index".into(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

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
    let result = auditor.audit_manifest(&stale_manifest).await;

    assert!(
        result.is_err(),
        "Auditor should reject signatures anchored to snapshots before authorization"
    );
}

/// **TEST: Executive Hijack (Negative)**
///
/// This test verifies that path-level authority is enforced.
/// An Executive key (m/1') is authorized for signing data, but it tries
/// to sign an administrative action (e.g., a new manifest for a graph).
/// The Auditor must reject this because only a Legislator key (m/0')
/// possesses administrative authority.
#[tokio::test]
async fn test_negative_executive_cannot_sign_administrative_action() {
    let mut store = InMemoryStore::new();
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // 1. Legislator Key (m/0')
    let alice_legislator =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/0'/0'").unwrap();
    let master_key = alice_legislator.public().signing_key().clone();

    // 2. Executive Key (m/1')
    let alice_phone =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/1'/0'").unwrap();

    // 3. Setup: Authorize the Phone via the Legislator
    let anchor_1 = create_valid_anchor(&mut store, &alice_legislator).await;

    // Explicitly authorize the Phone in a second identity snapshot
    let identity_key = GraphKey::new([0u8; 32]);
    let signer_hex = alice_phone
        .public()
        .signing_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let auth_block = Block::new(
        vec![],
        "akshara.auth.v1".into(),
        vec![],
        &identity_key,
        &alice_legislator,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    let mut credentials_map = std::collections::BTreeMap::new();
    credentials_map.insert(signer_hex, Address::from(auth_block.id()));

    let credentials_index = Block::new(
        serde_cbor::to_vec(&credentials_map).unwrap(),
        "akshara.index.v1".into(),
        vec![],
        &identity_key,
        &alice_legislator,
    )
    .unwrap();
    store.put_block(&credentials_index).await.unwrap();

    let mut root_map = std::collections::BTreeMap::new();
    root_map.insert(
        "credentials".to_string(),
        Address::from(credentials_index.id()),
    );

    let root_index = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "akshara.index.v1".into(),
        vec![],
        &identity_key,
        &alice_legislator,
    )
    .unwrap();
    store.put_block(&root_index).await.unwrap();

    let anchor = Manifest::new(
        GraphId::new(),
        root_index.id(),
        vec![anchor_1],
        anchor_1,
        &alice_legislator,
    );
    store.put_manifest(&anchor).await.unwrap();
    let _anchor_id = anchor.id();

    // 4. ATTACK: The Phone tries to sign a NEW genesis manifest for a resource graph.

    let root = crate::traversal::create_dummy_root();
    let null_anchor = ManifestId::from_sha256(&[0x00; 32]);
    let malicious_manifest = Manifest::new(GraphId::new(), root, vec![], null_anchor, &alice_phone);

    let auditor = Auditor::new(&store, master_key);

    // RED STATE: This SHOULD succeed currently (which is the failure we are testing)
    // because alice_phone IS authorized in the graph at anchor_id.
    let audit_res = auditor.audit_manifest(&malicious_manifest).await;

    assert!(
        audit_res.is_err(),
        "Auditor MUST reject non-legislator signatures for administrative actions"
    );
}

#[tokio::test]
async fn test_negative_invalid_derivation_paths() {
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // Test 1: Non-hardened path (Ed25519 must fail)
    let res = SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/0/0");
    assert!(res.is_err(), "Must reject non-hardened Ed25519 derivation");

    // Test 2: Malformed path
    let res = SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "invalid/path");
    assert!(res.is_err(), "Must reject malformed path string");

    // Test 3: Path with overflow index
    let res = SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/4294967296'");
    assert!(res.is_err(), "Must reject overflow derivation indices");
}

#[tokio::test]
async fn test_negative_path_hijack_prefix() {
    let mut store = InMemoryStore::new();
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice_legislator =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/0'/0'").unwrap();
    let master_key = alice_legislator.public().signing_key().clone();

    // The attacker creates a key at a path that LOOKS like a legislator but isn't.
    // E.g., appending an extra segment to bypass a naive 'contains' check.
    let malicious_key =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/1'/0'/0'")
            .unwrap();

    let anchor = create_valid_anchor(&mut store, &alice_legislator).await;
    let malicious_manifest = Manifest::new(
        GraphId::new(),
        crate::traversal::create_dummy_root(),
        vec![],
        anchor,
        &malicious_key,
    );

    let auditor = Auditor::new(&store, master_key);
    let res = auditor.audit_manifest(&malicious_manifest).await;

    // If our Auditor uses a strict check, this will fail.
    assert!(
        res.is_err(),
        "Auditor must reject keys from non-legislator branches even if they are authorized"
    );
}
