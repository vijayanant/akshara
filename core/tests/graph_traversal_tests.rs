use rand::rngs::OsRng;
use sovereign_core::graph::{BlockId, GraphWalker, Manifest, ManifestId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};
use uuid::Uuid;

fn create_chain(length: usize, store: &mut InMemoryStore) -> Vec<ManifestId> {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();
    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest = Manifest::new(doc_id, vec![], parents.clone(), &identity);
        store.put_manifest(&manifest).unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    ids
}

#[test]
fn can_find_ancestors_in_chain() {
    let mut store = InMemoryStore::new();
    let chain = create_chain(3, &mut store); // A -> B -> C

    let head = chain[2]; // C
    let mid = chain[1]; // B
    let root = chain[0]; // A

    let walker = GraphWalker::new(&store);
    let ancestors = walker.get_ancestors(&head).expect("Should traverse");

    assert!(ancestors.contains(&mid));
    assert!(ancestors.contains(&root));
    assert!(!ancestors.contains(&head));
}

#[test]
fn walker_handles_diamond_graph() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();
    let mut store = InMemoryStore::new();

    // A
    let a = Manifest::new(doc_id, vec![], vec![], &identity);
    store.put_manifest(&a).unwrap();

    // B -> A
    // Distinguish B from C by adding a dummy block to B
    let b_block = BlockId([0xB1; 32]);
    let b = Manifest::new(doc_id, vec![b_block], vec![a.id()], &identity);
    store.put_manifest(&b).unwrap();

    // C -> A
    let c = Manifest::new(doc_id, vec![], vec![a.id()], &identity);
    store.put_manifest(&c).unwrap();

    // D -> B, C
    let d = Manifest::new(doc_id, vec![], vec![b.id(), c.id()], &identity);
    store.put_manifest(&d).unwrap();

    let walker = GraphWalker::new(&store);
    let ancestors = walker.get_ancestors(&d.id()).unwrap();

    // Should contain A, B, C.
    assert!(ancestors.contains(&a.id()));
    assert!(ancestors.contains(&b.id()));
    assert!(ancestors.contains(&c.id()));

    // A should only be visited once (set ensures uniqueness, but we check correctness)
    assert_eq!(ancestors.len(), 3);
}

#[test]
fn walker_handles_missing_parent() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();
    let mut store = InMemoryStore::new();

    // A (Not stored)
    let a = Manifest::new(doc_id, vec![], vec![], &identity);

    // B -> A
    let b = Manifest::new(doc_id, vec![], vec![a.id()], &identity);
    store.put_manifest(&b).unwrap();

    let walker = GraphWalker::new(&store);

    let ancestors = walker.get_ancestors(&b.id()).unwrap();

    // It should find A (referenced by B), but stop there.
    assert_eq!(ancestors.len(), 1);
    assert!(ancestors.contains(&a.id()));
}

#[test]
fn walker_respects_graph_boundaries() {
    let mut store = InMemoryStore::new();

    // Chain 1: A -> B

    let chain1 = create_chain(2, &mut store);

    let _head1 = chain1[1];

    // Chain 2: X -> Y (Completely separate)

    let chain2 = create_chain(2, &mut store);
    let head2 = chain2[1];

    let walker = GraphWalker::new(&store);

    // Walk Chain 2
    let ancestors2 = walker.get_ancestors(&head2).unwrap();

    // Must contain X
    assert!(ancestors2.contains(&chain2[0]));

    // Must NOT contain A or B
    assert!(!ancestors2.contains(&chain1[0]));
    assert!(!ancestors2.contains(&chain1[1]));
}
