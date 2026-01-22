use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

fn create_dummy_content() -> BlockContent {
    let key = DocKey::new([0u8; 32]);
    let nonce = [0u8; 12];
    BlockContent::encrypt(&[], &key, nonce).unwrap()
}

#[test]
fn block_exposes_rank_for_ordering() {
    let identity = SecretIdentity::generate();
    let rank = "0.5";
    let block = Block::new(
        create_dummy_content(),
        rank.to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    assert_eq!(block.rank(), rank);
}

#[test]
fn block_has_type_metadata() {
    let identity = SecretIdentity::generate();
    let b_type = "h1";
    let block = Block::new(
        create_dummy_content(),
        "0.5".to_string(),
        b_type.to_string(),
        vec![],
        &identity,
    );
    assert_eq!(block.block_type(), b_type);
}
