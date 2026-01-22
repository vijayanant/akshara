use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_id_is_deterministic() {
    let identity = SecretIdentity::generate();
    let content = vec![0x1, 0x2, 0x3];
    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    let block1 = Block::new(
        content.clone(),
        rank.clone(),
        b_type.clone(),
        parents.clone(),
        &identity,
    );
    let block2 = Block::new(content, rank, b_type, parents, &identity);

    assert_eq!(
        block1.id(),
        block2.id(),
        "Identical blocks must have identical IDs"
    );
}

#[test]
fn block_id_is_unique_per_content() {
    let identity = SecretIdentity::generate();
    let block1 = Block::new(
        vec![0xA],
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    let block2 = Block::new(
        vec![0xB],
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
