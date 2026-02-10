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
    let graph_id = GraphId::new();

    // Remote peer says: "I have A"
    let request = SyncRequest::new(graph_id, vec![root]);
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
    let anchor = create_dummy_anchor();

    // Create two DIFFERENT content roots to force different CIDs
    let root_b = BlockId::from_sha256(&[0xB1; 32]);
    let root_c = BlockId::from_sha256(&[0xC1; 32]);

    // 2. Branch B (Child of A)
    let m_b = Manifest::new(graph_id, root_b, vec![m_a_id], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C (Child of A) - The Fork
    let m_c = Manifest::new(graph_id, root_c, vec![m_a_id], anchor, &identity);
    store.put_manifest(&m_c).unwrap();

    // Setup: Server has [B, C]. Client has [C].
    let local_heads = vec![m_b.id(), m_c.id()];
    let request = SyncRequest::new(graph_id, vec![m_c.id()]);

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    let missing = response.missing_manifests();
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&m_b.id())); // Client needs B
    assert!(!missing.contains(&m_c.id())); // Client has C
}

#[test]
fn sync_engine_returns_empty_if_already_synced() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(2, &mut store); // A -> B
    let local_heads = vec![chain[1]]; // B
    let graph_id = GraphId::new();
    let request = SyncRequest::new(graph_id, vec![chain[1]]); // B

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    assert!(response.missing_manifests().is_empty());
}

#[test]
fn sync_engine_ignores_unknown_remote_heads() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(1, &mut store); // A
    let local_heads = vec![chain[0]]; // A
    let graph_id = GraphId::new();

    // Remote sends Z (unknown)
    let unknown_head = ManifestId::from_sha256(&[0xFF; 32]);
    let request = SyncRequest::new(graph_id, vec![unknown_head]);

    let engine = SyncEngine::new(&store);
    let response = engine.calculate_response(&request, &local_heads).unwrap();

    assert_eq!(response.missing_manifests().len(), 1);
    assert_eq!(response.missing_manifests()[0], chain[0]);
}
