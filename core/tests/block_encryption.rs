use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_content_is_encrypted() {
    let identity = SecretIdentity::generate();
    let plaintext = b"Sensitive Sovereign Content".to_vec();
    let doc_key = DocKey::new([0x42u8; 32]);
    let nonce = [0u8; 12];

    // Feature: Content Encryption
    // Step 1: Encrypt outside the block (separation of concerns)
    let content = BlockContent::encrypt(&plaintext, &doc_key, nonce).expect("Encryption failed");

    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    let block = Block::new(content, rank, b_type, parents, &identity);

    // Requirement: Stored data must NOT be the plaintext
    assert_ne!(block.content().as_bytes(), plaintext);

    // Requirement: We must be able to decrypt it back
    let decrypted = block
        .content()
        .decrypt(&doc_key)
        .expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}
