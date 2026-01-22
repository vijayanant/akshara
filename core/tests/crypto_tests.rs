use rand::rngs::OsRng;
use serde_json::Value;
use sovereign_core::crypto::{BlockContent, DocKey, Lockbox};
use sovereign_core::identity::SecretIdentity;

#[test]
fn dockey_generation_is_random() {
    let mut rng = OsRng;
    let key1 = DocKey::generate(&mut rng);
    let key2 = DocKey::generate(&mut rng);

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Generated keys must be unique"
    );
}

#[test]
fn block_content_encryption_roundtrip() {
    let mut rng = OsRng;
    let key = DocKey::generate(&mut rng);
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
    let alice = SecretIdentity::generate(&mut rng); // Sender
    let bob = SecretIdentity::generate(&mut rng); // Recipient
    let doc_key = DocKey::generate(&mut rng);

    // Create lockbox for Bob
    let lockbox = Lockbox::create(bob.public().encryption_key(), &doc_key, &mut rng)
        .expect("Lockbox creation failed");

    // Bob opens it
    let unlocked_key = lockbox
        .open(bob.encryption_key())
        .expect("Bob should open lockbox");

    assert_eq!(unlocked_key.as_bytes(), doc_key.as_bytes());

    // Eve (Alice) tries to open Bob's lockbox with her own key
    let result = lockbox.open(alice.encryption_key());
    assert!(result.is_err(), "Wrong key must not open lockbox");
}

#[test]
fn lockbox_fails_on_tampered_ciphertext() {
    let mut rng = OsRng;
    let bob = SecretIdentity::generate(&mut rng);
    let doc_key = DocKey::generate(&mut rng);

    let lockbox = Lockbox::create(bob.public().encryption_key(), &doc_key, &mut rng).unwrap();

    // Tamper via JSON Value manipulation
    let mut val: Value = serde_json::to_value(&lockbox).unwrap();

    // Navigate: lockbox -> content -> ciphertext
    if let Some(arr) = val
        .get_mut("content")
        .and_then(|c| c.get_mut("ciphertext"))
        .and_then(|ct| ct.as_array_mut())
        .filter(|a| !a.is_empty())
    {
        // Flip the first byte
        let first = arr[0]
            .as_u64()
            .expect("Ciphertext element should be a number");
        arr[0] = serde_json::json!(first ^ 0xFF);
    }

    let tampered_lockbox: Lockbox = serde_json::from_value(val).unwrap();

    let result = tampered_lockbox.open(bob.encryption_key());
    assert!(
        result.is_err(),
        "Tampered ciphertext must fail AES-GCM auth tag check"
    );
}
