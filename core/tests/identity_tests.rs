use sovereign_core::identity::SecretIdentity;

#[test]
fn identity_can_be_generated_and_sign_messages() {
    // Feature: Sovereign Identity (RFC-005)
    // Requirement: A user can generate a secret identity and use it to sign messages.
    
    let secret_id = SecretIdentity::generate();
    let message = b"Sovereign V2 Test Message";
    
    let signature = secret_id.sign(message);
    let public_id = secret_id.public();
    
    assert!(public_id.verify(message, &signature), "Signature must be valid");
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
