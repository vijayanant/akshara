use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::{Block, BlockId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

// Helper to create a block pointing to parents
fn create_block(parents: Vec<BlockId>, store: &mut InMemoryStore) -> BlockId {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let key = DocKey::new([0u8; 32]);
    let content = BlockContent::encrypt(&[], &key, [0u8; 12]).unwrap();

    let block = Block::new(
        content,
        "a".to_string(),
        "p".to_string(),
        parents,
        &identity,
    );
    store.put_block(&block).unwrap();
    block.id()
}

#[test]
fn can_detect_block_ancestry() {
    let mut store = InMemoryStore::new();

    // A -> B -> C
    let a = create_block(vec![], &mut store);
    let b = create_block(vec![a], &mut store);
    let c = create_block(vec![b], &mut store);

    // We need logic to check if A is ancestor of C.
    // GraphWalker currently works on ManifestId.
    // We need a generic Walker or a specific BlockWalker.

    use sovereign_core::graph::BlockWalker;
    let walker = BlockWalker::new(&store);
    assert!(walker.is_ancestor(&c, &a).unwrap());
    assert!(!walker.is_ancestor(&a, &c).unwrap());
}
