use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_is_signed_by_author() {
    let secret_id = SecretIdentity::generate();
    let public_id = secret_id.public();

    let content = vec![1, 2, 3];
    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    let block = Block::new(content, [0u8; 12], rank, b_type, parents, &secret_id);

    assert_eq!(block.author_key(), public_id.signing_key());

    assert!(
        public_id.verify(&block.id(), block.signature()),
        "Block signature must be valid"
    );
}
