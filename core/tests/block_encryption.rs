use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_content_is_encrypted() {
    let identity = SecretIdentity::generate();
    let plaintext = b"Sensitive Sovereign Content".to_vec();
    let doc_key = [0x42u8; 32]; // AES-256 key

    let rank = "a".to_string();
    let b_type = "p".to_string();
    let parents = vec![];

    // Feature: Content Encryption
    // The constructor now takes a doc_key and plaintext,
    // and internally handles AES-GCM encryption.
    let block = Block::new_encrypted(
        plaintext.clone(),
        rank,
        b_type,
        parents,
        &identity,
        &doc_key,
    );

    // Requirement: Stored data must NOT be the plaintext
    assert_ne!(block.encrypted_data(), plaintext);

    // Requirement: We must be able to decrypt it back
    let decrypted = block.decrypt(&doc_key).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}
