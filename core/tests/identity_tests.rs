use rand::rngs::OsRng;
use sovereign_core::crypto::Signature;
use sovereign_core::identity::SecretIdentity;

#[test]
fn identity_can_be_generated_and_sign_messages() {
    let mut rng = OsRng;
    let secret_id = SecretIdentity::generate(&mut rng);
    let message = b"Sovereign V2 Test Message";

    let signature = secret_id.sign(message);
    let public_id = secret_id.public();

    assert!(
        public_id.verify(message, &signature),
        "Signature must be valid"
    );
}

#[test]
fn identity_is_deterministic_from_mnemonic() {
    let phrase = SecretIdentity::generate_mnemonic();

    let id1 = SecretIdentity::from_mnemonic(&phrase, "").expect("Failed to derive from mnemonic");
    let id2 = SecretIdentity::from_mnemonic(&phrase, "").expect("Failed to derive from mnemonic");

    assert_eq!(
        id1.public().signing_key(),
        id2.public().signing_key(),
        "Same mnemonic must yield same key"
    );
}

#[test]
fn identity_derivation_changes_with_passphrase() {
    let phrase = SecretIdentity::generate_mnemonic();

    let id_no_pass = SecretIdentity::from_mnemonic(&phrase, "").unwrap();
    let id_with_pass =
        SecretIdentity::from_mnemonic(&phrase, "correct horse battery staple").unwrap();

    assert_ne!(
        id_no_pass.public().signing_key(),
        id_with_pass.public().signing_key(),
        "Different passphrases must yield different keys"
    );
}

#[test]
fn identity_derivation_matches_bip39_standard_phrase() {
    // Verified BIP-39 phrase: 12x "abandon" with "about" as checksum word.
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let id = SecretIdentity::from_mnemonic(mnemonic, "");

    assert!(
        id.is_ok(),
        "Implementation must support standard BIP-39 phrases"
    );
    let id = id.unwrap();
    assert!(id.public().signing_key().as_bytes().iter().any(|&b| b != 0));
}

#[test]
fn identity_derivation_avalanche_effect() {
    let m1 = SecretIdentity::generate_mnemonic();
    let m2 = SecretIdentity::generate_mnemonic();

    assert_ne!(m1, m2);

    let id1 = SecretIdentity::from_mnemonic(&m1, "").unwrap();
    let id2 = SecretIdentity::from_mnemonic(&m2, "").unwrap();

    assert_ne!(
        id1.public().signing_key(),
        id2.public().signing_key(),
        "Different mnemonics must result in completely different keys"
    );
}

#[test]
fn identity_can_generate_valid_mnemonics() {
    let phrase = SecretIdentity::generate_mnemonic();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 12, "Should generate 12 words");

    let id = SecretIdentity::from_mnemonic(&phrase, "");
    assert!(
        id.is_ok(),
        "Generated mnemonic must be valid for derivation"
    );
}

// --- Negative Tests ---

#[test]
fn identity_verify_fails_on_wrong_message() {
    let mut rng = OsRng;
    let id = SecretIdentity::generate(&mut rng);
    let msg1 = b"message 1";
    let msg2 = b"message 2";
    let sig = id.sign(msg1);

    assert!(!id.public().verify(msg2, &sig));
}

#[test]
fn identity_verify_fails_on_wrong_signature() {
    let mut rng = OsRng;
    let id = SecretIdentity::generate(&mut rng);
    let msg = b"message";
    let bad_sig = Signature::new(vec![0u8; 64]);

    assert!(!id.public().verify(msg, &bad_sig));
}

#[test]
fn identity_fails_on_invalid_mnemonic() {
    // Too short
    let bad_mnemonic = "abandon abandon abandon";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic, "").is_err());

    // Invalid word
    let bad_mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic2, "").is_err());
}
