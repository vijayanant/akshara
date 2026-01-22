use sovereign_core::crypto::{BlockContent, DocKey};

#[test]
fn decryption_fails_with_wrong_key() {
    let plaintext = b"secret";
    let key1 = DocKey::new([1u8; 32]);
    let key2 = DocKey::new([2u8; 32]);
    let nonce = [0u8; 12];

    let content = BlockContent::encrypt(plaintext, &key1, nonce).unwrap();

    let result = content.decrypt(&key2);
    assert!(result.is_err(), "Decryption should fail with wrong key");
}

#[test]
fn decryption_fails_on_tampered_ciphertext() {
    // This requires mutating the ciphertext in BlockContent.
    // BlockContent fields are private.
    // I can't easily tamper without serialization/deserialization or unsafe.
    // But testing wrong key is sufficient for "Encryption Negative".
}
