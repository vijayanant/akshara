use crate::{
    BlockId, GraphId, ManifestId,
    graph::Manifest,
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::{
        create_chain, create_dummy_anchor, create_dummy_root, create_identity, walker::GraphWalker,
    },
};

#[test]
fn can_find_ancestors_in_chain() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(3, &mut store); // A -> B -> C

    let walker = GraphWalker::new(&store);
    let ancestors = walker.get_ancestors(&chain[2]).unwrap();

    assert_eq!(ancestors.len(), 2);
    assert!(ancestors.contains(&chain[0]));
    assert!(ancestors.contains(&chain[1]));
}

#[test]
fn walker_handles_diamond_graph() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();

    // 1. Root A
    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    store.put_manifest(&m_a).unwrap();

    // 2. Branch B -> A (Add a unique block)
    let b_block = BlockId::from_sha256(&[0xB1; 32]);
    let m_b = Manifest::new(graph_id, b_block, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C -> A (Add a different unique block)
    let c_block = BlockId::from_sha256(&[0xC1; 32]);
    let m_c = Manifest::new(graph_id, c_block, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_c).unwrap();

    // 4. Merge D -> B, C
    let m_d = Manifest::new(graph_id, root, vec![m_b.id(), m_c.id()], anchor, &identity);
    store.put_manifest(&m_d).unwrap();

    let walker = GraphWalker::new(&store);
    let ancestors = walker.get_ancestors(&m_d.id()).unwrap();

    // Should find A, B, and C
    assert_eq!(ancestors.len(), 3);
    assert!(ancestors.contains(&m_a.id()));
    assert!(ancestors.contains(&m_b.id()));
    assert!(ancestors.contains(&m_c.id()));
}

#[test]
fn walker_handles_missing_parent() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let root = create_dummy_root();
    let anchor = create_dummy_anchor();

    // Manifest B pointing to A, but A is not in store
    let a_id = ManifestId::from_sha256(&[0xEE; 32]);
    let m_b = Manifest::new(graph_id, root, vec![a_id], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    let walker = GraphWalker::new(&store);
    let ancestors = walker.get_ancestors(&m_b.id()).unwrap();

    assert_eq!(ancestors.len(), 1);
    assert!(ancestors.contains(&a_id));
}

#[test]
fn walker_respects_graph_boundaries() {
    let mut store = InMemoryStore::new();

    // Chain 1: A -> B
    let chain1 = create_chain(2, &mut store);

    // Chain 2: X -> Y
    let chain2 = create_chain(2, &mut store);
    let head2 = chain2[1];

    let walker = GraphWalker::new(&store);
    let ancestors2 = walker.get_ancestors(&head2).unwrap();

    assert!(ancestors2.contains(&chain2[0]));
    assert!(!ancestors2.contains(&chain1[0]));
    assert!(!ancestors2.contains(&chain1[1]));
}
