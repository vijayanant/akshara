use sovereign_core::crypto::{DocKey, Lockbox};
use sovereign_core::identity::SecretIdentity;

#[test]
fn lockbox_can_be_opened_by_recipient() {
    let _alice = SecretIdentity::generate(); // Sender (unused in creation, we just need key)
    let bob = SecretIdentity::generate(); // Recipient
    let doc_key = DocKey::new([0x99u8; 32]);

    // Create lockbox for Bob
    // Note: Lockbox::create generates its own ephemeral sender key.
    let lockbox =
        Lockbox::create(bob.public().encryption_key(), &doc_key).expect("Lockbox creation failed");

    // Bob opens it
    let unlocked_key = lockbox
        .open(bob.encryption_key())
        .expect("Bob should open lockbox");

    assert_eq!(unlocked_key, doc_key);
}

#[test]
fn lockbox_cannot_be_opened_by_wrong_person() {
    let bob = SecretIdentity::generate();
    let eve = SecretIdentity::generate();
    let doc_key = DocKey::new([0x99u8; 32]);

    let lockbox = Lockbox::create(bob.public().encryption_key(), &doc_key).unwrap();

    // Eve tries to open
    assert!(lockbox.open(eve.encryption_key()).is_err());
}
