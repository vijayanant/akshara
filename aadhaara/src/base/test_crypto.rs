use crate::base::crypto::{
    BlockContent, EncryptionPublicKey, EncryptionSecretKey, GraphKey, Lockbox, SigningPublicKey,
};
use rand::rngs::OsRng;
use serde_json::Value;

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
    let nonce = [0u8; 12];

    let content = BlockContent::encrypt(plaintext, &key, nonce).expect("Encryption failed");

    // Authenticated encryption: ciphertext length = plaintext + tag (16 bytes)
    assert_eq!(content.as_bytes().len(), plaintext.len() + 16);
    assert_ne!(content.as_bytes(), plaintext);

    let decrypted = content.decrypt(&key).expect("Decryption failed");
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

    let mut val: Value = serde_json::to_value(&lockbox).unwrap();

    if let Some(arr) = val
        .get_mut("content")
        .and_then(|c| c.get_mut("ciphertext"))
        .and_then(|ct| ct.as_array_mut())
        .filter(|a| !a.is_empty())
    {
        let first = arr[0]
            .as_u64()
            .expect("Ciphertext element should be a number");
        arr[0] = serde_json::json!(first ^ 0xFF);
    }

    let tampered_lockbox: Lockbox = serde_json::from_value(val).unwrap();
    let result = tampered_lockbox.open(&bob_secret);

    assert!(
        result.is_err(),
        "Tampered ciphertext must fail AES-GCM auth tag check"
    );
}

#[test]
fn signing_verify_fails_on_malformed_signature() {
    let msg = b"test";
    let public_key = SigningPublicKey::new([0u8; 32]);

    // Wrong length (not 64)
    let bad_sig = crate::base::crypto::Signature::new(vec![0u8; 32]);
    let result = public_key.verify(msg, &bad_sig);

    assert!(result.is_err());
}
