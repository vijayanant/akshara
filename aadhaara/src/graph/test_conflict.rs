use rand::rngs::OsRng;

use crate::{
    BlockId, GraphId,
    graph::Manifest,
    identity::SecretIdentity,
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::{create_dummy_root, create_valid_anchor, walker::GraphWalker},
};

// Helper function

pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

#[tokio::test]
async fn can_find_manifest_lca() {
    let store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let root = create_dummy_root();
    let anchor = create_valid_anchor(&store, &identity).await;

    // 1. Root A
    let m_a = Manifest::new(graph_id, root, vec![], anchor, &identity);
    store.put_manifest(&m_a).await.unwrap();

    // 2. Branch B -> A
    let b_block = BlockId::from_sha256(&[0xB1; 32]);
    let m_b = Manifest::new(graph_id, b_block, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_b).await.unwrap();

    // 3. Branch C -> A
    let c_block = BlockId::from_sha256(&[0xC1; 32]);
    let m_c = Manifest::new(graph_id, c_block, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_c).await.unwrap();

    // 4. Find LCA of B and C
    let walker = GraphWalker::new(&store, identity.public().signing_key().clone());
    let lca = walker.find_lca(&m_b.id(), &m_c.id()).await.unwrap();

    assert_eq!(lca, Some(m_a.id()));
}

#[tokio::test]
async fn can_diff_forked_manifests() {
    let store = InMemoryStore::new();
    let identity = create_identity();
    let graph_id = GraphId::new();
    let anchor = create_valid_anchor(&store, &identity).await;

    // Common Ancestor A
    let m_a = Manifest::new(graph_id, create_dummy_root(), vec![], anchor, &identity);
    store.put_manifest(&m_a).await.unwrap();

    // Left B (adds block 1)
    let b1 = BlockId::from_sha256(&[1u8; 32]);
    let m_b = Manifest::new(graph_id, b1, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_b).await.unwrap();

    // Right C (adds block 2)
    let b2 = BlockId::from_sha256(&[2u8; 32]);
    let m_c = Manifest::new(graph_id, b2, vec![m_a.id()], anchor, &identity);
    store.put_manifest(&m_c).await.unwrap();
}
