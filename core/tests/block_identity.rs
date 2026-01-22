use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

fn create_dummy_content(data: &[u8]) -> BlockContent {
    let key = DocKey::new([0u8; 32]);
    let nonce = [0u8; 12];
    BlockContent::encrypt(data, &key, nonce).unwrap()
}

#[test]
fn block_id_is_deterministic() {
    let identity = SecretIdentity::generate();
    let content_bytes = vec![0x1, 0x2, 0x3];
    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    // We use the helper to create identical BlockContent (same data, key, nonce)
    let content1 = create_dummy_content(&content_bytes);
    let content2 = create_dummy_content(&content_bytes);

    let block1 = Block::new(
        content1,
        rank.clone(),
        b_type.clone(),
        parents.clone(),
        &identity,
    );
    let block2 = Block::new(content2, rank, b_type, parents, &identity);

    assert_eq!(
        block1.id(),
        block2.id(),
        "Identical blocks must have identical IDs"
    );
}

#[test]
fn block_id_is_unique_per_content() {
    let identity = SecretIdentity::generate();

    // Different content
    let content1 = create_dummy_content(&[0xA]);
    let content2 = create_dummy_content(&[0xB]);

    let block1 = Block::new(
        content1,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    let block2 = Block::new(
        content2,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );

    assert_ne!(
        block1.id(),
        block2.id(),
        "Different content must produce different IDs"
    );
}
