mod common;
use common::*;
use sovereign_core::graph::{BlockId, DocId, Manifest};
use sovereign_core::store::{GraphStore, InMemoryStore};
use uuid::Uuid;

#[test]
fn store_can_save_and_load_manifest() {
    let identity = create_identity();
    let doc_id = DocId::new();
    let manifest = Manifest::new(doc_id, vec![], vec![], &identity);

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
    let (identity, doc_id) = (create_identity(), Uuid::new_v4().into());

    // 1. Root Manifest (A)
    let m_a = Manifest::new(doc_id, vec![], vec![], &identity);
    store.put_manifest(&m_a).unwrap();

    let heads = store.get_heads(&doc_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_a.id());

    // 2. Child Manifest (B) -> Parent A
    let m_b = Manifest::new(doc_id, vec![], vec![m_a.id()], &identity);
    store.put_manifest(&m_b).unwrap();

    let heads = store.get_heads(&doc_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_b.id()); // A should be removed, B added
}

#[test]
fn store_tracks_multiple_heads_on_fork() {
    let mut store = InMemoryStore::new();
    let (identity, doc_id) = (create_identity(), Uuid::new_v4().into());

    // Root A
    let m_a = Manifest::new(doc_id, vec![], vec![], &identity);
    store.put_manifest(&m_a).unwrap();

    // Fork B -> A
    let m_b = Manifest::new(doc_id, vec![], vec![m_a.id()], &identity);
    store.put_manifest(&m_b).unwrap();

    // Fork C -> A (Must differ from B content-wise)
    let unique_block = BlockId([0xFF; 32]);
    let m_c = Manifest::new(doc_id, vec![unique_block], vec![m_a.id()], &identity);
    store.put_manifest(&m_c).unwrap();

    let heads = store.get_heads(&doc_id).unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads.contains(&m_b.id()));
    assert!(heads.contains(&m_c.id()));
    assert!(!heads.contains(&m_a.id()));
}

#[test]
fn store_merges_heads() {
    let mut store = InMemoryStore::new();
    let (identity, doc_id) = (create_identity(), Uuid::new_v4().into());

    // Setup Fork: B, C
    let m_a = Manifest::new(doc_id, vec![], vec![], &identity);
    let m_b = Manifest::new(doc_id, vec![], vec![m_a.id()], &identity);

    // Fork C needs unique content
    let unique_block = BlockId([0xFF; 32]);
    let m_c = Manifest::new(doc_id, vec![unique_block], vec![m_a.id()], &identity);

    store.put_manifest(&m_a).unwrap();
    store.put_manifest(&m_b).unwrap();
    store.put_manifest(&m_c).unwrap();

    // Merge D -> B, C
    let m_d = Manifest::new(doc_id, vec![], vec![m_b.id(), m_c.id()], &identity);
    store.put_manifest(&m_d).unwrap();

    let heads = store.get_heads(&doc_id).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0], m_d.id());
}

#[test]
fn store_handles_out_of_order_insertion() {
    // This documents the LIMITATION (FIXME) we noted.
    // If Child arrives before Parent, both might remain as heads.
    let mut store = InMemoryStore::new();
    let (identity, doc_id) = (create_identity(), Uuid::new_v4().into());

    let m_a = Manifest::new(doc_id, vec![], vec![], &identity);
    let m_b = Manifest::new(doc_id, vec![], vec![m_a.id()], &identity);

    // 1. Insert Child B first
    store.put_manifest(&m_b).unwrap();

    // 2. Insert Parent A second
    store.put_manifest(&m_a).unwrap();

    let heads = store.get_heads(&doc_id).unwrap();

    // Ideally, only B is head.
    // But our current simplistic logic only removes *referenced parents*.
    // When A is added, it has no parents, so it's a head.
    // We don't check if A is *already referenced* by B.

    assert!(heads.contains(&m_b.id()));
    assert!(heads.contains(&m_a.id())); // A is technically a "False Head" here
}
