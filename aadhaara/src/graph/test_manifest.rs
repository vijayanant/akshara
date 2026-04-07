use crate::graph::Manifest;
use crate::graph::manifest::ManifestHeader;
use crate::traversal::create_identity;
use crate::{Address, AksharaSigner, BlockId, GraphId, ManifestId};

#[test]
fn manifest_integrity_success() {
    let identity = create_identity();
    let graph_id = GraphId::new();
    let content_root = BlockId::from_sha256(&[1u8; 32]);
    let parents = vec![ManifestId::from_sha256(&[2u8; 32])];
    let anchor = ManifestId::null();

    let manifest = Manifest::new(
        graph_id,
        content_root,
        parents,
        anchor,
        Address::null(),
        &identity,
        None,
    );

    assert!(manifest.verify_integrity().is_ok());
}

#[test]
fn manifest_identity_anchor_mismatch_fails() {
    let identity = create_identity();
    let graph_id = GraphId::new();
    let content_root = BlockId::from_sha256(&[1u8; 32]);
    let valid_anchor = ManifestId::from_sha256(&[5u8; 32]);

    let manifest = Manifest::new(
        graph_id,
        content_root,
        vec![],
        valid_anchor,
        Address::null(),
        &identity,
        None,
    );

    assert!(manifest.verify_integrity().is_ok());

    // Tamper with identity anchor
    let mut tampered = manifest;
    tampered.header.identity_anchor = ManifestId::from_sha256(&[9u8; 32]);

    assert!(
        tampered.verify_integrity().is_err(),
        "Tampered identity anchor must be detected (ID mismatch)"
    );
}

#[test]
fn manifest_integrity_fails_on_tampered_content_root() {
    let identity = create_identity();
    let mut manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    // Tamper
    manifest.header.content_root = BlockId::from_sha256(&[9u8; 32]);

    assert!(manifest.verify_integrity().is_err());
}

#[test]
fn manifest_integrity_fails_on_tampered_metadata() {
    let identity = create_identity();
    let mut manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    // Tamper creation time
    manifest.header.created_at += 1;

    assert!(manifest.verify_integrity().is_err());
}

#[test]
fn manifest_integrity_fails_on_tampered_signature() {
    let identity = create_identity();
    let mut manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    // Tamper signature by just changing one byte
    let mut sig_bytes = manifest.signature().as_bytes().to_vec();
    sig_bytes[0] ^= 0xFF;
    manifest.signature = crate::base::crypto::Signature::new(sig_bytes);

    assert!(manifest.verify_integrity().is_err());
}

#[test]
fn manifest_id_depends_on_content_root_and_authority() {
    let id_a = create_identity();
    let id_b = create_identity();
    let graph_id = GraphId::new();
    let content_root = BlockId::from_sha256(&[1u8; 32]);
    let parents = vec![];
    let anchor = ManifestId::null();

    let m1 = Manifest::new(
        graph_id,
        content_root,
        parents.clone(),
        anchor,
        Address::null(),
        &id_a,
        None,
    );
    let m2 = Manifest::new(
        graph_id,
        content_root,
        parents,
        anchor,
        Address::null(),
        &id_b,
        None,
    );

    assert_ne!(
        m1.id(),
        m2.id(),
        "Manifest ID must include author public key"
    );
}

#[test]
fn manifest_is_signed_by_author() {
    let identity = create_identity();
    let manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    assert_eq!(manifest.author(), &identity.public_key());
}

#[test]
fn manifest_restores_from_raw_parts() {
    let identity = create_identity();
    let original = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    let header = ManifestHeader {
        graph_id: original.graph_id(),
        content_root: original.content_root(),
        parents: original.parents().to_vec(),
        identity_anchor: original.identity_anchor(),
        schema_anchor: original.schema_anchor(),
        signer_path_hash: *original.signer_path_hash(),
        authority_proof: None,
        created_at: original.created_at(),
    };

    let restored = Manifest::from_raw_parts(
        original.id(),
        header,
        original.author().clone(),
        original.signature().clone(),
    );

    assert_eq!(original.id(), restored.id());
    assert_eq!(original.graph_id(), restored.graph_id());
    assert!(restored.verify_integrity().is_ok());
}

#[test]
fn manifest_parent_cycle_detection() {
    let identity = create_identity();
    let graph_id = GraphId::new();
    let content_root = BlockId::from_sha256(&[1u8; 32]);
    let anchor = ManifestId::null();

    // Create a normal manifest first
    let parent_manifest = Manifest::new(
        graph_id,
        content_root,
        vec![],
        anchor,
        Address::null(),
        &identity,
        None,
    );

    // Create child that references parent
    let child_manifest = Manifest::new(
        graph_id,
        content_root,
        vec![parent_manifest.id()],
        anchor,
        Address::null(),
        &identity,
        None,
    );

    // Both should be valid
    assert!(parent_manifest.verify_integrity().is_ok());
    assert!(child_manifest.verify_integrity().is_ok());

    // Note: Actual cycle detection happens during GraphWalker traversal,
    // not during manifest verification. The manifest structure itself
    // can contain any parent references - cycles are detected during walk.
}
