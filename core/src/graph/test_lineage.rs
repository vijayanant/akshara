use rand::rngs::OsRng;

use crate::{
    BlockId, GraphKey,
    graph::Block,
    identity::SecretIdentity,
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::walker::BlockWalker,
};

// Helper to create a block pointing to parents
fn create_block(parents: Vec<BlockId>, store: &mut InMemoryStore) -> BlockId {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let key = GraphKey::from([0u8; 32]);

    let block = Block::new(vec![], "p".to_string(), parents, &key, &identity)
        .expect("Failed to create block");
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

    let walker = BlockWalker::new(&store);
    assert!(walker.is_ancestor(&c, &a).unwrap());
    assert!(!walker.is_ancestor(&a, &c).unwrap());
}
