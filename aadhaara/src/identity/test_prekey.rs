use crate::base::address::GraphId;
use crate::base::crypto::{EncryptionPublicKey, GraphKey, Lockbox};
use crate::identity::SecretIdentity;
use crate::identity::types::MasterIdentity;

#[test]
fn test_prekey_derivation_isolation() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();

    // 1. Derive two different pre-keys from Branch 3
    // Path: m/44'/999'/0'/3'/<device>'/<index>'
    let pk0 = master.derive_child("m/44'/999'/0'/3'/0'/0'").unwrap();
    let pk1 = master.derive_child("m/44'/999'/0'/3'/0'/1'").unwrap();

    // 2. MUST be isolated from each other
    assert_ne!(pk0.public().encryption_key(), pk1.public().encryption_key());

    // 3. MUST be isolated from the Executive (Branch 1) key
    let exec = master.derive_child("m/44'/999'/0'/1'/0'").unwrap();
    assert_ne!(
        pk0.public().encryption_key(),
        exec.public().encryption_key()
    );
}

#[test]
fn test_prekey_asynchronous_handshake() {
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice_master = MasterIdentity::from_mnemonic(&alice_mnemonic, "").unwrap();

    // Alice generates a Pre-Key for her "Mailbox"
    let prekey_index = 42;
    let device_index = 0;
    let alice_prekey_secret = alice_master
        .derive_child(&format!(
            "m/44'/999'/0'/3'/{}'/{}'",
            device_index, prekey_index
        ))
        .unwrap();
    let alice_prekey_public = alice_prekey_secret.public().encryption_key().clone();

    // --- Bob is offline/separate ---
    let _shared_graph_id = GraphId::new();
    let shared_graph_key = GraphKey::generate(&mut rand::thread_rng());

    // Bob "finds" Alice's Pre-Key #42 on the Relay and creates a Lockbox
    let lockbox = Lockbox::create(
        &alice_prekey_public,
        &shared_graph_key,
        &mut rand::thread_rng(),
    )
    .unwrap();

    // --- Alice wakes up ---
    // She sees Bob's lockbox and the tag "Pre-Key #42"
    let recovered_alice_prekey = alice_master
        .derive_child(&format!(
            "m/44'/999'/0'/3'/{}'/{}'",
            device_index, prekey_index
        ))
        .unwrap();

    let opened_key = lockbox
        .open(recovered_alice_prekey.encryption_key())
        .unwrap();

    assert_eq!(opened_key, shared_graph_key);
}

#[test]
fn test_prekey_bundle_integrity() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();

    // 1. Alice creates a bundle of 10 pre-keys for her first device (index 0)
    let bundle = master.generate_pre_key_bundle(0, 0, 10).unwrap();

    // 2. Verify basic properties
    assert_eq!(bundle.pre_keys.len(), 10);
    assert!(bundle.pre_keys.contains_key(&0));
    assert!(bundle.pre_keys.contains_key(&9));

    // 3. Verify cryptographic integrity
    assert!(bundle.verify().is_ok());

    // 4. Negative Case: Tamper with a pre-key in the bundle
    let mut malicious_bundle = bundle.clone();
    let fake_key = EncryptionPublicKey::new([0u8; 32]);
    malicious_bundle.pre_keys.insert(0, fake_key);

    assert!(
        malicious_bundle.verify().is_err(),
        "Bundle verification must fail if a key is tampered"
    );
}
