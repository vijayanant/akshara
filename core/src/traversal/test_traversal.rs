use crate::{
    BlockId, GraphId, ManifestId,
    base::crypto::SovereignSigner,
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

#[test]
fn walker_handles_manifest_cycles_gracefully() {
    let mut store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let anchor = create_dummy_anchor();
    let root = create_dummy_root();

    // To test cycles in ancestors, we must use from_raw_parts to force a self-pointer
    let cycle_id = ManifestId::from_sha256(&[0x99; 32]);
    let header = crate::graph::ManifestHeader {
        graph_id,
        content_root: root,
        parents: vec![cycle_id], // Point to self!
        identity_anchor: anchor,
        created_at: 12345,
    };

    let signature = identity.sign(cycle_id.as_ref());
    let malicious_manifest = crate::graph::Manifest::from_raw_parts(
        cycle_id,
        header,
        identity.public().signing_key().clone(),
        signature,
    );

    store.put_manifest(&malicious_manifest).unwrap();

    let walker = GraphWalker::new(&store);
    // Should complete without infinite loop
    let ancestors = walker.get_ancestors(&cycle_id).unwrap();

    // It found itself as a parent, but the visited set should stop it.
    assert!(ancestors.contains(&cycle_id));
}
