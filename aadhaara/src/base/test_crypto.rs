use crate::base::crypto::{
    BlockContent, EncryptionPublicKey, EncryptionSecretKey, GraphKey, Lockbox,
};
use rand::rngs::OsRng;

#[test]
fn dockey_generation_is_random() {
    let mut rng = OsRng;
    let k1 = GraphKey::generate(&mut rng);
    let k2 = GraphKey::generate(&mut rng);
    assert_ne!(k1, k2);
}

#[test]
fn block_content_encryption_roundtrip() {
    let mut rng = OsRng;
    let key = GraphKey::generate(&mut rng);
    let plaintext = b"Hello Sovereign Crypto";
    let nonce = [0u8; 24]; // XChaCha20 nonce
    let ad = b"context-binding-ad";

    let content = BlockContent::encrypt(plaintext, &key, nonce, ad).expect("Encryption failed");

    // Authenticated encryption: ciphertext length = plaintext + tag (16 bytes)
    assert_eq!(content.as_bytes().len(), plaintext.len() + 16);
    assert_ne!(content.as_bytes(), plaintext);

    let decrypted = content.decrypt(&key, ad).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn lockbox_lifecycle() {
    let mut rng = OsRng;
    let graph_key = GraphKey::generate(&mut rng);

    // Generate real X25519 keys for Bob
    let bob_secret_bytes = [2u8; 32];
    let bob_secret = EncryptionSecretKey::new(bob_secret_bytes);
    let bob_public = EncryptionPublicKey::new(
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret_bytes))
            .as_bytes(),
    );

    // Create lockbox for Bob
    let lockbox = Lockbox::create(&bob_public, &graph_key, &mut rng).expect("Lockbox failed");

    // Bob opens it
    let unlocked_key = lockbox.open(&bob_secret).expect("Open failed");
    assert_eq!(unlocked_key.as_bytes(), graph_key.as_bytes());

    // Alice's key (wrong key)
    let alice_secret = EncryptionSecretKey::new([1u8; 32]);
    let result = lockbox.open(&alice_secret);
    assert!(result.is_err(), "Wrong key must not open lockbox");
}

#[test]
fn lockbox_fails_on_tampered_ciphertext() {
    let mut rng = OsRng;
    let bob_secret_bytes = [7u8; 32];
    let bob_secret = EncryptionSecretKey::new(bob_secret_bytes);
    let bob_public = EncryptionPublicKey::new(
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret_bytes))
            .as_bytes(),
    );
    let graph_key = GraphKey::generate(&mut rng);
    let lockbox = Lockbox::create(&bob_public, &graph_key, &mut rng).unwrap();

    let bytes = crate::base::encoding::to_canonical_bytes(&lockbox).unwrap();

    // Tamper: Flip a bit in the CBOR bytes (this will hit the ciphertext or tag)
    let mut fuzzed = bytes.clone();
    let len = fuzzed.len();
    fuzzed[len - 5] ^= 0xFF;

    let decode_res: Result<Lockbox, _> = crate::base::encoding::from_canonical_bytes(&fuzzed[..]);

    if let Ok(tampered_lockbox) = decode_res {
        let result = tampered_lockbox.open(&bob_secret);
        assert!(
            result.is_err(),
            "Tampered ciphertext must fail XChaCha20-Poly1305 auth tag check"
        );
    }
}

#[test]
fn signing_verify_fails_on_malformed_signature() {
    let msg = b"test";
    let public_key = crate::base::crypto::SigningPublicKey::new([0u8; 32]);

    // Wrong length (not 64)
    let bad_sig = crate::base::crypto::Signature::new(vec![0u8; 32]);
    let result = public_key.verify(msg, &bad_sig);

    assert!(result.is_err());
}

#[test]
fn signature_verify_fails_on_truncated_message() {
    use crate::base::crypto::AksharaSigner;
    use rand::rngs::OsRng;

    let identity = crate::identity::SecretIdentity::generate(&mut OsRng);
    let msg = b"This is a test message that will be truncated";
    let signature = identity.sign(msg);

    // Verify with full message should work
    let result_ok = identity.public().signing_key().verify(msg, &signature);
    assert!(result_ok.is_ok());

    // Verify with truncated message MUST fail
    let truncated_msg = &msg[..10];
    let result_truncated = identity
        .public()
        .signing_key()
        .verify(truncated_msg, &signature);
    assert!(
        result_truncated.is_err(),
        "Signature verification must fail with truncated message"
    );
}
