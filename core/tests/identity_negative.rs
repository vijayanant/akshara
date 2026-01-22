use sovereign_core::crypto::Signature;
use sovereign_core::identity::SecretIdentity;

#[test]
fn identity_verify_fails_on_wrong_message() {
    let id = SecretIdentity::generate();
    let msg1 = b"message 1";
    let msg2 = b"message 2";
    let sig = id.sign(msg1);

    assert!(!id.public().verify(msg2, &sig));
}

#[test]
fn identity_verify_fails_on_wrong_signature() {
    let id = SecretIdentity::generate();
    let msg = b"message";

    // Create a dummy signature (64 bytes of zeros)
    let bad_sig = Signature::new(vec![0u8; 64]);

    // Ed25519 verification should fail (or return error which map to false)
    assert!(!id.public().verify(msg, &bad_sig));
}
