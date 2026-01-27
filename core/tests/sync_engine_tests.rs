mod common;
use common::*;
use rand::rngs::OsRng;
use sovereign_core::graph::{BlockId, Manifest, ManifestId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};
use sovereign_core::sync::{SyncEngine, SyncRequest};
use uuid::Uuid;

#[test]
fn sync_engine_identifies_missing_manifests() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(3, &mut store); // A -> B -> C

    let root = chain[0]; // A
    let local_heads = vec![chain[2]]; // C

    // Remote peer says: "I have A"
    let request = SyncRequest::new(vec![root]);
    let engine = SyncEngine::new(&store);

    let response = engine
        .calculate_response(&request, &local_heads)
        .expect("Diff calculation failed");

    let missing = response.missing_manifests();
    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&chain[1])); // B
    assert!(missing.contains(&chain[2])); // C
}

#[test]
fn sync_engine_handles_forks() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();
    let mut store = InMemoryStore::new();

    // 1. Root A
    let m_a = Manifest::new(doc_id, vec![], vec![], &identity);
    store.put_manifest(&m_a).unwrap();

    // 2. Branch B (Child of A)
    let b_block = BlockId([0xB1; 32]);
    let m_b = Manifest::new(doc_id, vec![b_block], vec![m_a.id()], &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C (Child of A) - The Fork
    let c_block = BlockId([0xC1; 32]);
    let m_c = Manifest::new(doc_id, vec![c_block], vec![m_a.id()], &identity);
    store.put_manifest(&m_c).unwrap();

    // Setup: Server has [B, C]. Client has [C].
    let local_heads = vec![m_b.id(), m_c.id()];
    let request = SyncRequest::new(vec![m_c.id()]);

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    let missing = response.missing_manifests();
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&m_b.id())); // Client needs B
    assert!(!missing.contains(&m_c.id())); // Client has C
    assert!(!missing.contains(&m_a.id())); // Client has A (via C)
}

#[test]
fn sync_engine_returns_empty_if_already_synced() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(2, &mut store); // A -> B
    let local_heads = vec![chain[1]]; // B
    let request = SyncRequest::new(vec![chain[1]]); // B

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    assert!(response.missing_manifests().is_empty());
    assert!(response.missing_blocks().is_empty());
}

#[test]
fn sync_engine_ignores_unknown_remote_heads() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(1, &mut store); // A
    let local_heads = vec![chain[0]]; // A

    // Remote sends Z (unknown)
    let unknown_head = ManifestId([0xFF; 32]);
    let request = SyncRequest::new(vec![unknown_head]);

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    // Missing = Local(A) - Remote(Z).
    // Remote(Z) traversal fails immediately, so Remote Known = {Z}.
    // A is not in {Z}.
    // So Server returns A.
    assert_eq!(response.missing_manifests().len(), 1);
    assert_eq!(response.missing_manifests()[0], chain[0]);
}
