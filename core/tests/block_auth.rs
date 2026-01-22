use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_is_signed_by_author() {
    let secret_id = SecretIdentity::generate();
    let public_id = secret_id.public();

    let content_bytes = vec![1, 2, 3];
    let key = DocKey::new([0u8; 32]);
    let nonce = [0u8; 12];
    let content = BlockContent::encrypt(&content_bytes, &key, nonce).unwrap();

    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    let block = Block::new(content, rank, b_type, parents, &secret_id);

    // author_key() now returns &SigningPublicKey
    assert_eq!(block.author(), public_id.signing_key());

    // verify expects &[u8] for message
    assert!(
        public_id.verify(block.id().as_ref(), block.signature()),
        "Block signature must be valid"
    );
}
