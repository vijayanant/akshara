use rand::rngs::OsRng;
use sovereign_core::crypto::Signature;
use sovereign_core::identity::SecretIdentity;

#[test]
fn identity_can_be_generated_and_sign_messages() {
    // Feature: Sovereign Identity (RFC-005)
    // Requirement: A user can generate a secret identity and use it to sign messages.

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
    // Feature: Mnemonic Identity (RFC-005)
    // Requirement: Same mnemonic phrase must yield the same Identity.

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let id1 = SecretIdentity::from_mnemonic(mnemonic).expect("Failed to derive from mnemonic");
    let id2 = SecretIdentity::from_mnemonic(mnemonic).expect("Failed to derive from mnemonic");

    assert_eq!(id1.public().signing_key(), id2.public().signing_key());
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

    // Create a dummy signature (64 bytes of zeros)
    let bad_sig = Signature::new(vec![0u8; 64]);

    // Ed25519 verification should fail (or return error which map to false)
    assert!(!id.public().verify(msg, &bad_sig));
}

#[test]
fn identity_fails_on_invalid_mnemonic() {
    // Too short
    let bad_mnemonic = "abandon abandon abandon";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic).is_err());

    // Invalid word
    let bad_mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic2).is_err());
}
