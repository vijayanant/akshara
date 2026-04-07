use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::error::{AksharaError, IntegrityError};
use crate::graph::{Block, BlockType, Manifest};
use crate::identity::SecretIdentity;
use crate::identity::types::MasterIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::auditor::Auditor;
use crate::traversal::create_valid_anchor;
use rand::rngs::OsRng;

/// **TEST: Identity Graph Swap (Negative)**
///
/// This test verifies that a signer cannot "borrow" someone else's authority.
/// Bob signs a manifest but points the `identity_anchor` to Alice's identity graph.
/// Since Bob is not an authorized device in Alice's graph, the walk will fail
/// to find his public key, and the manifest must be rejected.
#[tokio::test]
async fn test_negative_identity_graph_swap() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();

    let alice = SecretIdentity::generate(&mut rng).unwrap();
    let bob = SecretIdentity::generate(&mut rng).unwrap();

    // 1. Setup Alice's real anchor (Alice is authorized in her own graph)
    let alice_anchor = create_valid_anchor(&store, &alice).await;

    // 2. Bob tries to sign a manifest but points to ALICE'S identity graph
    let graph_id = GraphId::new();
    let root = BlockId::from_sha256(&[0xEE; 32]);

    let forged_manifest = Manifest::new(
        graph_id,
        root,
        vec![],
        alice_anchor,
        Address::null(),
        &bob, // Bob signs, but uses Alice's history
        None,
    );

    // The Auditor expects Alice's root
    let auditor = Auditor::new(&store);

    // Audit must fail because Bob is not authorized in Alice's history
    let result = auditor.audit_manifest(&forged_manifest, None).await;
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
    let store = InMemoryStore::new();
    let alice = SecretIdentity::generate(&mut rng).unwrap();

    // 1. Genesis State (Master Key only)
    let genesis_anchor = create_valid_anchor(&store, &alice).await;

    // 2. Device A is added in a NEW identity snapshot
    let device_a_mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let device_a = SecretIdentity::from_mnemonic(&device_a_mnemonic, "").unwrap();
    let identity_key = crate::identity::graph::IDENTITY_GRAPH_KEY;
    let signer_hex = device_a.public().signing_key().to_hex();

    // 1. Create the authorization block (The Leaf)
    let auth_block = crate::graph::Block::new(
        GraphId::new(), // Pass a new GraphId for testing
        vec![],
        crate::graph::BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    // 2. Use IndexBuilder to construct the hierarchical path: credentials/<pubkey>
    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            &format!("credentials/{}", signer_hex),
            crate::base::address::Address::from(auth_block.id()),
        )
        .unwrap();

    let root_index_id = builder
        .build(GraphId::new(), &store, &alice, &identity_key)
        .await
        .unwrap();

    let _snapshot_2 = Manifest::new(
        GraphId::new(),
        root_index_id,
        vec![genesis_anchor],
        genesis_anchor,
        Address::null(),
        &alice,
        None,
    );
    // (We don't even need to store snapshot_2 for this test, because we are testing Device A anchoring to genesis_anchor)

    // 3. ATTACK: Device A tries to sign a manifest anchored to the GENESIS snapshot
    // (Before it was authorized!)
    let stale_manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[0x11; 32]),
        vec![],
        genesis_anchor,
        Address::null(),
        &device_a,
        None,
    );

    let auditor = Auditor::new(&store);
    let result = auditor.audit_manifest(&stale_manifest, None).await;

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
    let store = InMemoryStore::new();
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // 1. Legislator Key (m/0')
    let alice_legislator =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/0'/0'").unwrap();

    // 2. Executive Key (m/1')
    let alice_phone =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/1'/0'").unwrap();

    // 3. Setup: Authorize the Phone via the Legislator
    let anchor_1 = create_valid_anchor(&store, &alice_legislator).await;

    // Explicitly authorize the Phone in a second identity snapshot
    let identity_key = crate::identity::graph::IDENTITY_GRAPH_KEY;
    let signer_hex = alice_phone.public().signing_key().to_hex();

    let auth_block = Block::new(
        GraphId::new(),
        vec![],
        crate::graph::BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        &alice_legislator,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            &format!("credentials/{}", signer_hex),
            Address::from(auth_block.id()),
        )
        .unwrap();

    let root_index_id = builder
        .build(GraphId::new(), &store, &alice_legislator, &identity_key)
        .await
        .unwrap();

    let anchor = Manifest::new(
        GraphId::new(),
        root_index_id,
        vec![anchor_1],
        anchor_1,
        Address::null(),
        &alice_legislator,
        None,
    );
    store.put_manifest(&anchor).await.unwrap();
    let _anchor_id = anchor.id();

    // 4. ATTACK: The Phone tries to sign a NEW genesis manifest for a resource graph.

    let root = crate::traversal::create_dummy_root();
    let null_anchor = ManifestId::null();
    let malicious_manifest = Manifest::new(
        GraphId::new(),
        root,
        vec![],
        null_anchor,
        Address::null(),
        &alice_phone,
        None,
    );

    let auditor = Auditor::new(&store);

    // RED STATE: This SHOULD succeed currently (which is the failure we are testing)
    // because alice_phone IS authorized in the graph at anchor_id.
    let audit_res = auditor.audit_manifest(&malicious_manifest, None).await;

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
    let store = InMemoryStore::new();
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice_legislator =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/0'/0'").unwrap();

    // The attacker creates a key at a path that LOOKS like a legislator but isn't.
    // E.g., appending an extra segment to bypass a naive 'contains' check.
    let malicious_key =
        SecretIdentity::from_mnemonic_at_path(&alice_mnemonic, "", "m/44'/999'/0'/1'/0'/0'")
            .unwrap();

    let anchor = create_valid_anchor(&store, &alice_legislator).await;
    let malicious_manifest = Manifest::new(
        GraphId::new(),
        crate::traversal::create_dummy_root(),
        vec![],
        anchor,
        Address::null(),
        &malicious_key,
        None,
    );

    let auditor = Auditor::new(&store);
    let res = auditor.audit_manifest(&malicious_manifest, None).await;

    // If our Auditor uses a strict check, this will fail.
    assert!(
        res.is_err(),
        "Auditor must reject keys from non-legislator branches even if they are authorized"
    );
}

#[tokio::test]
async fn test_adversarial_ghost_branch_rejection() {
    let store = InMemoryStore::new();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let master = MasterIdentity::from_mnemonic(mnemonic, "").unwrap();

    // 1. Genesis: Alice (Master) is the root.
    let gid = GraphId::new();
    let gkey = crate::identity::graph::IDENTITY_GRAPH_KEY;
    let alice = master.derive_child("m/44'/999'/0'/0'/0'", None).unwrap();

    // 2. Authorize a Laptop
    let laptop = master.derive_child("m/44'/999'/0'/1'/0'", None).unwrap();
    let laptop_pub = laptop.public().signing_key().clone();

    let auth_block = Block::new(
        gid,
        laptop_pub.as_bytes().to_vec(),
        BlockType::AksharaAuthV1,
        vec![],
        &gkey,
        &alice,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            &format!("credentials/{}", laptop_pub.to_hex()),
            auth_block.id().into(),
        )
        .unwrap();
    let id_root = builder.build(gid, &store, &alice, &gkey).await.unwrap();

    let id_manifest_v1 = Manifest::new(
        gid,
        id_root,
        vec![],
        ManifestId::null(),
        Address::null(),
        &alice,
        None,
    );
    store.put_manifest(&id_manifest_v1).await.unwrap();

    // 3. Revoke the Laptop in ID_V2
    let revoke_block = Block::new(
        gid,
        laptop_pub.as_bytes().to_vec(),
        BlockType::AksharaRevocationV1,
        vec![auth_block.id()],
        &gkey,
        &alice,
    )
    .unwrap();
    store.put_block(&revoke_block).await.unwrap();

    let mut builder_v2 = crate::traversal::IndexBuilder::new();
    builder_v2
        .insert(
            &format!("credentials/{}", laptop_pub.to_hex()),
            revoke_block.id().into(),
        )
        .unwrap();
    let id_root_v2 = builder_v2.build(gid, &store, &alice, &gkey).await.unwrap();

    let id_manifest_v2 = Manifest::new(
        gid,
        id_root_v2,
        vec![id_manifest_v1.id()],
        id_manifest_v1.id(),
        Address::null(),
        &alice,
        None,
    );
    store.put_manifest(&id_manifest_v2).await.unwrap();

    // 4. THE ATTACK: The "revoked" laptop tries to create a new data manifest
    // It anchors to ID_V1 (where it was still valid) to try and bypass the revocation.
    let data_root = BlockId::from_sha256(&[0xEE; 32]);
    let ghost_manifest = Manifest::new(
        GraphId::new(),
        data_root,
        vec![],
        id_manifest_v1.id(),
        Address::null(),
        &laptop,
        None,
    );

    // 5. THE AUDIT:
    // A naive auditor (no frontier) would accept this.
    // Our hardened Auditor (with latest_identity) MUST reject it.
    let auditor = Auditor::new(&store).with_latest_identity(id_manifest_v2.id());

    let result = auditor.audit_manifest(&ghost_manifest, None).await;

    match result {
        Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(msg))) => {
            assert!(
                msg.contains("revoked in the latest state"),
                "Error should mention revocation at frontier: {}",
                msg
            );
        }
        other => panic!(
            "Auditor should have rejected Ghost Branch with UnauthorizedSigner error, got: {:?}",
            other
        ),
    }
}

/// **TEST: Revocation Detection Without Latest Identity (High Severity Fix)**
///
/// This test verifies that even when no "latest" identity state is available
/// (e.g., syncing a shared graph where we only see the peer's anchor),
/// the Auditor still detects revocations at the anchor itself.
///
/// Scenario:
/// 1. Alice creates a genesis identity anchor
/// 2. Alice authorizes a device (phone)
/// 3. Alice revokes the phone
/// 4. The phone tries to sign a manifest anchored to the post-revocation state
/// 5. The Auditor (with latest_identity=None) must reject the manifest
#[tokio::test]
async fn test_revocation_detected_without_latest_identity() {
    let mut rng = OsRng;
    let store = InMemoryStore::new();
    let identity_key = crate::identity::graph::IDENTITY_GRAPH_KEY;

    // 1. Alice's genesis (Legislator root)
    let alice = SecretIdentity::generate(&mut rng).unwrap();
    let genesis_anchor = create_valid_anchor(&store, &alice).await;

    // 2. Create and authorize a phone device
    let phone = SecretIdentity::generate(&mut rng).unwrap();
    let signer_hex = phone.public().signing_key().to_hex();

    let auth_block = Block::new(
        GraphId::new(),
        vec![],
        BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    let mut builder = crate::traversal::IndexBuilder::new();
    builder
        .insert(
            &format!("credentials/{}", signer_hex),
            Address::from(auth_block.id()),
        )
        .unwrap();

    let root_index_id = builder
        .build(GraphId::new(), &store, &alice, &identity_key)
        .await
        .unwrap();

    let anchor_with_phone = Manifest::new(
        GraphId::new(),
        root_index_id,
        vec![genesis_anchor],
        genesis_anchor,
        Address::null(),
        &alice,
        None,
    );
    let anchor_with_phone_id = anchor_with_phone.id();
    store.put_manifest(&anchor_with_phone).await.unwrap();

    // 3. Revoke the phone — add a revocation entry
    let revocation_block = Block::new(
        GraphId::new(),
        vec![],
        BlockType::AksharaRevocationV1,
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    store.put_block(&revocation_block).await.unwrap();

    let mut builder2 = crate::traversal::IndexBuilder::new();
    builder2
        .insert(
            &format!("revocations/{}", signer_hex),
            Address::from(revocation_block.id()),
        )
        .unwrap();

    let root_after_revocation = builder2
        .build(GraphId::new(), &store, &alice, &identity_key)
        .await
        .unwrap();

    let anchor_after_revocation = Manifest::new(
        GraphId::new(),
        root_after_revocation,
        vec![anchor_with_phone_id],
        anchor_with_phone_id,
        Address::null(),
        &alice,
        None,
    );
    let anchor_after_revocation_id = anchor_after_revocation.id();
    store.put_manifest(&anchor_after_revocation).await.unwrap();

    // 4. The revoked phone signs a data manifest anchored to the post-revocation state
    let data_graph_id = GraphId::new();
    let root = BlockId::from_sha256(&[0xDD; 32]);

    let revoked_manifest = Manifest::new(
        data_graph_id,
        root,
        vec![],
        anchor_after_revocation_id, // Anchored to state AFTER revocation
        Address::null(),
        &phone, // Signed by the revoked phone
        None,
    );

    // 5. Auditor with latest_identity=None must still reject
    let auditor = Auditor::new(&store);
    let result = auditor.audit_manifest(&revoked_manifest, None).await;

    assert!(
        result.is_err(),
        "Auditor should reject manifest signed by a revoked device, even without latest_identity"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            AksharaError::Integrity(IntegrityError::UnauthorizedSigner(_))
        ),
        "Should fail with UnauthorizedSigner (revoked)"
    );
}

/// **TEST: Auditor Rejects Manifest with Missing Identity Anchor (Issue #2)**
///
/// During sync, manifests can arrive out of order. If a data manifest references
/// an identity_anchor that hasn't arrived yet, the Auditor should reject it
/// rather than crashing or accepting blindly.
///
/// Scenario:
/// 1. Alice creates an identity anchor (genesis)
/// 2. Alice signs a data manifest pointing to a NEW anchor that doesn't exist yet
/// 3. The Auditor must reject it — the identity anchor is missing
#[tokio::test]
async fn test_auditor_rejects_manifest_with_missing_identity_anchor() {
    let store = InMemoryStore::new();
    let alice = SecretIdentity::generate(&mut OsRng).unwrap();
    create_valid_anchor(&store, &alice).await;

    // Create a fake identity anchor that doesn't exist in the store
    let fake_identity_anchor = ManifestId::from_sha256(&[0xCC; 32]);

    // Sign a data manifest pointing to the missing identity anchor
    let graph_id = GraphId::new();
    let root = BlockId::from_sha256(&[0xDD; 32]);
    let manifest = Manifest::new(
        graph_id,
        root,
        vec![],
        fake_identity_anchor,
        Address::null(),
        &alice,
        None,
    );

    let auditor = Auditor::new(&store);
    let result = auditor.audit_manifest(&manifest, Some(&graph_id)).await;

    assert!(
        result.is_err(),
        "Auditor should reject manifest when identity_anchor is missing"
    );
    assert!(
        matches!(result.unwrap_err(), AksharaError::Store(_)),
        "Should fail with Store error (identity anchor not found)"
    );

    // Now create a real identity anchor and retry — should pass
    let identity_anchor = create_valid_anchor(&store, &alice).await;

    let manifest2 = Manifest::new(
        graph_id,
        root,
        vec![],
        identity_anchor,
        Address::null(),
        &alice,
        None,
    );
    let auditor = Auditor::new(&store);
    assert!(
        auditor
            .audit_manifest(&manifest2, Some(&graph_id))
            .await
            .is_ok(),
        "Auditor should accept when identity anchor exists"
    );
}

/// **TEST: Auditor Rejects Manifests from Wrong Graph (Issue #1/#5 Fix)**
///
/// This test verifies that the Auditor rejects manifests whose `graph_id`
/// does not match the expected graph. Without this check, a malicious peer
/// could inject data manifests from a completely different graph and the
/// Auditor would accept them as valid.
///
/// Scenario:
/// 1. Alice creates an identity anchor
/// 2. Alice signs a manifest for graph_a
/// 3. Alice signs a manifest for graph_b
/// 4. Auditor is auditing graph_a and receives the graph_b manifest
/// 5. Auditor must reject it
#[tokio::test]
async fn test_auditor_rejects_manifest_from_wrong_graph() {
    use crate::traversal::auditor::Auditor;

    let store = InMemoryStore::new();
    let alice = SecretIdentity::generate(&mut OsRng).unwrap();
    let anchor = create_valid_anchor(&store, &alice).await;

    // Manifest for graph_a — valid
    let graph_a = GraphId::new();
    let root_a = BlockId::from_sha256(&[0xAA; 32]);
    let manifest_a = Manifest::new(
        graph_a,
        root_a,
        vec![],
        anchor,
        Address::null(),
        &alice,
        None,
    );

    // Manifest for graph_b — also valid internally, but WRONG graph
    let graph_b = GraphId::new();
    let root_b = BlockId::from_sha256(&[0xBB; 32]);
    let manifest_b = Manifest::new(
        graph_b,
        root_b,
        vec![],
        anchor,
        Address::null(),
        &alice,
        None,
    );

    // Auditor auditing graph_a receives graph_b's manifest
    let auditor = Auditor::new(&store);
    let result = auditor.audit_manifest(&manifest_b, Some(&graph_a)).await;

    assert!(
        result.is_err(),
        "Auditor should reject manifest from wrong graph_id"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            AksharaError::Integrity(IntegrityError::GraphIdMismatch(..))
        ),
        "Should fail with GraphIdMismatch error"
    );

    // But the same manifest from the CORRECT graph should pass
    let auditor = Auditor::new(&store);
    let result = auditor.audit_manifest(&manifest_a, Some(&graph_a)).await;
    assert!(
        result.is_ok(),
        "Auditor should accept manifest from correct graph_id"
    );
}
