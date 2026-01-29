use rand::rngs::OsRng;
use sovereign_core::graph::{BlockId, GraphId, GraphWalker, Manifest};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

#[test]
fn can_find_manifest_lca() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let mut store = InMemoryStore::new();

    // A
    let a = Manifest::new(graph_id, vec![], vec![], &identity);
    store.put_manifest(&a).unwrap();

    // B -> A
    let b_block = BlockId([0xB1; 32]);
    let b = Manifest::new(graph_id, vec![b_block], vec![a.id()], &identity);
    store.put_manifest(&b).unwrap();

    // C -> A
    let c_block = BlockId([0xC1; 32]);
    let c = Manifest::new(graph_id, vec![c_block], vec![a.id()], &identity);
    store.put_manifest(&c).unwrap();

    let walker = GraphWalker::new(&store);

    // LCA(B, C) should be A
    let lca = walker.find_lca(&b.id(), &c.id()).unwrap();
    assert_eq!(lca, Some(a.id()));
}

#[test]
fn can_diff_forked_manifests() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();

    let b1 = BlockId([1u8; 32]);

    let b2 = BlockId([2u8; 32]);
    let b3 = BlockId([3u8; 32]);

    // Base: [1]
    let base = Manifest::new(graph_id, vec![b1], vec![], &identity);

    // Left: [2] (Replaced 1 with 2)
    let left = Manifest::new(graph_id, vec![b2], vec![base.id()], &identity);

    // Right: [3] (Replaced 1 with 3)
    let right = Manifest::new(graph_id, vec![b3], vec![base.id()], &identity);

    // Diff Logic
    let diff = left.diff(&right, Some(&base));

    assert_eq!(diff.left_only, vec![b2]);
    assert_eq!(diff.right_only, vec![b3]);
}
