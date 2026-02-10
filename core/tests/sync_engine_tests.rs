mod common;
use common::*;
use sovereign_core::graph::{BlockId, GraphId, Manifest, ManifestId};
use sovereign_core::store::{GraphStore, InMemoryStore};
use sovereign_core::sync::{SyncEngine, SyncRequest};

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
    let mut store = InMemoryStore::new();
    let chain = create_chain(1, &mut store); // A
    let m_a_id = chain[0];

    let identity = create_identity();
    let graph_id = GraphId::new();

    // 2. Branch B (Child of A)
    let b_block = BlockId::from_sha256(&[0xB1; 32]);
    let m_b = Manifest::new(graph_id, vec![b_block], vec![m_a_id], &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C (Child of A) - The Fork
    let c_block = BlockId::from_sha256(&[0xC1; 32]);
    let m_c = Manifest::new(graph_id, vec![c_block], vec![m_a_id], &identity);
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
    assert!(!missing.contains(&m_a_id)); // Client has A (via C)
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
    let unknown_head = ManifestId::from_sha256(&[0xFF; 32]);
    let request = SyncRequest::new(vec![unknown_head]);

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    assert_eq!(response.missing_manifests().len(), 1);
    assert_eq!(response.missing_manifests()[0], chain[0]);
}
