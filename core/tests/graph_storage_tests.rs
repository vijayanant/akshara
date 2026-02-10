mod common;
use common::*;
use sovereign_core::graph::{Block, GraphId, Manifest};
use sovereign_core::store::{GraphStore, InMemoryStore};
use uuid::Uuid;

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
