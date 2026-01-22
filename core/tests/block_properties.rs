use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_exposes_rank_for_ordering() {
    let identity = SecretIdentity::generate();
    let rank = "0.5";
    let block = Block::new(vec![], rank.to_string(), "p".to_string(), vec![], &identity);
    assert_eq!(block.rank(), rank);
}

#[test]
fn block_has_type_metadata() {
    let identity = SecretIdentity::generate();
    let b_type = "h1";
    let block = Block::new(
        vec![],
        "0.5".to_string(),
        b_type.to_string(),
        vec![],
        &identity,
    );
    assert_eq!(block.block_type(), b_type);
}
