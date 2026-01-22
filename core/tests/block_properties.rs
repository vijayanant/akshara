use sovereign_core::graph::Block;

#[test]
fn block_exposes_rank_for_ordering() {
    let rank = "0.5";
    let block = Block::new(vec![], rank.to_string(), "p".to_string(), vec![]);
    assert_eq!(block.rank(), rank);
}

#[test]
fn block_has_type_metadata() {
    let b_type = "h1";
    let block = Block::new(vec![], "0.5".to_string(), b_type.to_string(), vec![]);
    assert_eq!(block.block_type(), b_type);
}
