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

    // This constructor now requires an identity to satisfy the "Authorization" feature.
    // This will cause a compilation error (Red).
    let block = Block::new(content, rank, b_type, parents, &secret_id);

    // Verify the author key is stored.
    assert_eq!(block.author_key(), public_id.signing_key());

    // Verify the signature is valid over the ID.
    assert!(
        public_id.verify(block.id().as_ref(), block.signature()),
        "Block signature must be valid"
    );
}
