use rand::rngs::OsRng;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    BlockId, GraphId, GraphKey, ManifestId,
    graph::{Block, Manifest},
    identity::SecretIdentity,
    state::{GraphStore, in_memory_store::InMemoryStore},
};

// Helper functions

pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

pub fn create_dummy_key() -> GraphKey {
    GraphKey::generate(&mut OsRng)
}

pub fn create_dummy_anchor() -> ManifestId {
    ManifestId::from_sha256(&[0u8; 32])
}

pub fn create_dummy_root() -> BlockId {
    BlockId::from_sha256(&[0xFFu8; 32])
}

#[test]
fn store_can_save_and_load_manifest() {
    let identity = create_identity();
    let graph_id = GraphId::new();
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();
    let manifest = Manifest::new(graph_id, root, vec![], anchor, &identity);

    let mut store = InMemoryStore::new();
    store.put_manifest(&manifest).expect("Save failed");

    let loaded = store
        .get_manifest(&manifest.id())
        .expect("Load failed")
        .expect("Manifest not found");

    assert_eq!(loaded.id(), manifest.id());
}

#[test]
fn store_tracks_single_head_linear_history() {
    let mut store = InMemoryStore::new();
    let (identity, graph_id) = (create_identity(), Uuid::new_v4().into());
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();

    // 1. Root Manifest (A)
    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    store.put_manifest(&m_a).unwrap();

    let heads = store.get_heads(&graph_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_a.id());

    // 2. Child Manifest (B) -> Parent A
    let m_b = Manifest::new(graph_id, root, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    let heads = store.get_heads(&graph_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_b.id()); // A should be removed, B added
}

#[test]
fn store_tracks_multiple_heads_on_fork() {
    let mut store = InMemoryStore::new();
    let (identity, graph_id) = (create_identity(), Uuid::new_v4().into());
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();
    let key = create_dummy_key();

    // Root A
    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    store.put_manifest(&m_a).unwrap();

    // Fork B -> A
    let m_b = Manifest::new(graph_id, root, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    // Fork C -> A (Must differ from B content-wise)
    let unique_block =
        Block::new(b"unique".to_vec(), "p".to_string(), vec![], &key, &identity).unwrap();
    store.put_block(&unique_block).unwrap();

    let m_c = Manifest::new(
        graph_id,
        unique_block.id(),
        vec![m_a.id()],
        anchor,
        &identity,
    );
    store.put_manifest(&m_c).unwrap();

    let heads = store.get_heads(&graph_id).unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads.contains(&m_b.id()));
    assert!(heads.contains(&m_c.id()));
    assert!(!heads.contains(&m_a.id()));
}

#[test]
fn store_merges_heads() {
    let mut store = InMemoryStore::new();
    let (identity, graph_id) = (create_identity(), Uuid::new_v4().into());
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();
    let key = create_dummy_key();

    // Setup Fork: B, C
    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    let m_b = Manifest::new(graph_id, root, vec![m_a.id()], anchor, &identity);

    // Fork C needs unique content
    let unique_block = Block::new(
        b"unique2".to_vec(),
        "p".to_string(),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&unique_block).unwrap();
    let m_c = Manifest::new(
        graph_id,
        unique_block.id(),
        vec![m_a.id()],
        anchor,
        &identity,
    );

    store.put_manifest(&m_a).unwrap();
    store.put_manifest(&m_b).unwrap();
    store.put_manifest(&m_c).unwrap();

    // Merge D -> B, C
    let m_d = Manifest::new(graph_id, root, vec![m_b.id(), m_c.id()], anchor, &identity);
    store.put_manifest(&m_d).unwrap();

    let heads = store.get_heads(&graph_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_d.id());
}

#[test]
fn store_handles_out_of_order_insertion() {
    let mut store = InMemoryStore::new();
    let (identity, graph_id) = (create_identity(), Uuid::new_v4().into());
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();

    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    let m_b = Manifest::new(graph_id, root, vec![m_a.id()], anchor, &identity);

    // 1. Insert Child B first
    store.put_manifest(&m_b).unwrap();

    // 2. Insert Parent A second
    store.put_manifest(&m_a).unwrap();

    let heads = store.get_heads(&graph_id).unwrap();
    assert!(heads.contains(&m_b.id()));
    assert!(heads.contains(&m_a.id()));
}

#[test]
#[ignore]
fn store_rwlock_torture_test() {
    use std::sync::Barrier;
    use std::thread;

    let store = Arc::new(InMemoryStore::new());
    let barrier = Arc::new(Barrier::new(100));
    let mut handles = vec![];

    // 1. Writer Threads (50)
    for i in 0..50 {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut store = (*store_clone).clone();
            let block = Block::from_raw_parts(
                BlockId::from_sha256(&[i as u8; 32]),
                crate::base::crypto::SigningPublicKey::new([0; 32]),
                crate::base::crypto::Signature::new(vec![]),
                crate::base::crypto::BlockContent::encrypt(
                    &[],
                    &crate::GraphKey::new([0; 32]),
                    [0; 12],
                )
                .unwrap(),
                "test".to_string(),
                vec![],
            );

            barrier_clone.wait();
            store.put_block(&block).unwrap();
        }));
    }

    // 2. Reader Threads (50)
    for i in 0..50 {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        let graph_id = GraphId::new();
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            let _ = store_clone
                .get_block(&BlockId::from_sha256(&[i as u8; 32]))
                .unwrap();
            let _ = store_clone.get_heads(&graph_id).unwrap();
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
