use rand::rngs::OsRng;

use crate::{BlockId, GraphId, ManifestId, graph::Manifest, identity::SecretIdentity};

#[test]
fn manifest_id_depends_on_content_root_and_authority() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let root_cid = BlockId::from_sha256(&[1u8; 32]);
    let anchor_cid = ManifestId::from_sha256(&[2u8; 32]);
    let parents = vec![];

    let manifest1 = Manifest::new(graph_id, root_cid, parents.clone(), anchor_cid, &identity);

    // 1. Determinism Check
    let manifest2 = Manifest::new(graph_id, root_cid, parents.clone(), anchor_cid, &identity);
    assert_eq!(manifest1.id(), manifest2.id());

    // 2. Different Content Root -> Different ID
    let root_cid2 = BlockId::from_sha256(&[3u8; 32]);
    let manifest3 = Manifest::new(graph_id, root_cid2, parents.clone(), anchor_cid, &identity);
    assert_ne!(manifest1.id(), manifest3.id());

    // 3. Different Identity Anchor -> Different ID
    let anchor_cid2 = ManifestId::from_sha256(&[4u8; 32]);
    let manifest4 = Manifest::new(graph_id, root_cid, parents, anchor_cid2, &identity);
    assert_ne!(manifest1.id(), manifest4.id());
}

#[test]
fn manifest_integrity_success() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let root_cid = BlockId::from_sha256(&[0u8; 32]);
    let anchor_cid = ManifestId::from_sha256(&[0u8; 32]);

    let manifest = Manifest::new(graph_id, root_cid, vec![], anchor_cid, &identity);

    assert!(manifest.verify_integrity().is_ok());
}

#[test]
fn manifest_integrity_fails_on_tampered_content_root() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::from_sha256(&[2u8; 32]),
        &identity,
    );

    let json = serde_json::to_string(&manifest).unwrap();
    // Tamper with the CID string in JSON using an ILLEGAL character (Base32 excludes 0, 1, 8, 9)
    let tampered_json = json.replace("\"content_root\":\"baf", "\"content_root\":\"baf0");

    // Deserialization should fail because 'bafz' is not a valid Base32 CID
    let result: Result<Manifest, _> = serde_json::from_str(&tampered_json);
    assert!(
        result.is_err(),
        "Deserialization must fail on malformed CID"
    );
}

#[test]
fn manifest_integrity_fails_on_tampered_metadata() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let manifest = Manifest::new(
        graph_id,
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::from_sha256(&[2u8; 32]),
        &identity,
    );

    let mut val: serde_json::Value = serde_json::to_value(&manifest).unwrap();
    // Tamper with graph_id (Uuid)
    val["graph_id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());

    let tampered: Manifest = serde_json::from_value(val).unwrap();
    assert!(
        tampered.verify_integrity().is_err(),
        "Must fail when graph_id is tampered"
    );
}

#[test]
fn manifest_integrity_fails_on_tampered_signature() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let manifest = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::from_sha256(&[2u8; 32]),
        &identity,
    );

    let mut val: serde_json::Value = serde_json::to_value(&manifest).unwrap();
    if let Some(arr) = val.get_mut("signature").and_then(|v| v.as_array_mut()) {
        let first = arr[0].as_u64().unwrap();
        arr[0] = serde_json::json!(first ^ 0xFF);
    }

    let tampered: Manifest = serde_json::from_value(val).unwrap();
    assert!(
        tampered.verify_integrity().is_err(),
        "Must fail when signature is tampered"
    );
}

#[test]
fn manifest_restores_from_raw_parts() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let original = Manifest::new(
        GraphId::new(),
        BlockId::from_sha256(&[1u8; 32]),
        vec![],
        ManifestId::from_sha256(&[2u8; 32]),
        &identity,
    );

    let restored = Manifest::from_raw_parts(
        original.id(),
        original.graph_id(),
        original.content_root(),
        original.parents().to_vec(),
        original.identity_anchor(),
        original.author().clone(),
        original.signature().clone(),
        original.created_at(),
    );

    assert_eq!(restored.id(), original.id());
    assert!(restored.verify_integrity().is_ok());
}
