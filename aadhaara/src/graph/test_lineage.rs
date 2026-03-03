use rand::rngs::OsRng;

use crate::{
    BlockId, GraphKey,
    graph::Block,
    identity::SecretIdentity,
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::walker::BlockWalker,
};

// Helper to create a block pointing to parents
async fn create_block(parents: Vec<BlockId>, store: &mut InMemoryStore) -> BlockId {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let key = GraphKey::from([0u8; 32]);

    let block = Block::new(
        vec![],
        crate::graph::BlockType::from("p"),
        parents,
        &key,
        &identity,
    )
    .expect("Failed to create block");
    store.put_block(&block).await.unwrap();
    block.id()
}

#[tokio::test]
async fn can_detect_block_ancestry() {
    let mut store = InMemoryStore::new();

    // A -> B -> C
    let a = create_block(vec![], &mut store).await;
    let b = create_block(vec![a], &mut store).await;
    let c = create_block(vec![b], &mut store).await;

    let walker = BlockWalker::new(&store);
    assert!(walker.is_ancestor(&c, &a).await.unwrap());
    assert!(!walker.is_ancestor(&a, &c).await.unwrap());
}
