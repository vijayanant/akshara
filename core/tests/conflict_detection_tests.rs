mod common;
use common::*;
use sovereign_core::graph::{BlockId, GraphId, GraphWalker, Manifest};
use sovereign_core::store::{GraphStore, InMemoryStore};

#[test]
fn can_find_manifest_lca() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();

    // 1. Root A
    let m_a = Manifest::new(graph_id, vec![], vec![], &identity);
    store.put_manifest(&m_a).unwrap();

    // 2. Branch B -> A
    let b_block = BlockId::from_sha256(&[0xB1; 32]);
    let m_b = Manifest::new(graph_id, vec![b_block], vec![m_a.id()], &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C -> A
    let c_block = BlockId::from_sha256(&[0xC1; 32]);
    let m_c = Manifest::new(graph_id, vec![c_block], vec![m_a.id()], &identity);
    store.put_manifest(&m_c).unwrap();

    // 4. Find LCA of B and C
    let walker = GraphWalker::new(&store);
    let lca = walker.find_lca(&m_b.id(), &m_c.id()).unwrap();

    assert_eq!(lca, Some(m_a.id()));
}

#[test]
fn can_diff_forked_manifests() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();

    // Common Ancestor A
    let m_a = Manifest::new(graph_id, vec![], vec![], &identity);
    store.put_manifest(&m_a).unwrap();

    // Left B (adds block 1)
    let b1 = BlockId::from_sha256(&[1u8; 32]);
    let m_b = Manifest::new(graph_id, vec![b1], vec![m_a.id()], &identity);
    store.put_manifest(&m_b).unwrap();

    // Right C (adds block 2)
    let b2 = BlockId::from_sha256(&[2u8; 32]);
    let m_c = Manifest::new(graph_id, vec![b2], vec![m_a.id()], &identity);
    store.put_manifest(&m_c).unwrap();

    // Diff
    let diff = m_b.diff(&m_c, Some(&m_a));

    assert_eq!(diff.left_only, vec![b1]);
    assert_eq!(diff.right_only, vec![b2]);
}
