use sovereign_core::graph::Block;

#[test]
fn block_id_is_deterministic() {
    // Feature: Content Addressing
    // Requirement: Two blocks with identical content and metadata must have the same ID.
    
    let content = vec![0x1, 0x2, 0x3];
    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    let block1 = Block::new(content.clone(), rank.clone(), b_type.clone(), parents.clone());
    let block2 = Block::new(content, rank, b_type, parents);

    assert_eq!(block1.id(), block2.id(), "Identical blocks must have identical IDs");
}

#[test]
fn block_id_is_unique_per_content() {
    // Requirement: Changing content changes the ID.
    let block1 = Block::new(vec![0xA], "a".to_string(), "p".to_string(), vec![]);
    let block2 = Block::new(vec![0xB], "a".to_string(), "p".to_string(), vec![]);

    assert_ne!(block1.id(), block2.id(), "Different content must produce different IDs");
}