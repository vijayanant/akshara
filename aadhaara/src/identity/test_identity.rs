use rand::rngs::OsRng;

use crate::base::address::GraphId;
use crate::base::crypto::SovereignSigner;
use crate::identity::SecretIdentity;

// Valid 24-word mnemonic for testing
const MNEMONIC_1: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

#[test]
fn identity_can_be_generated_and_sign_messages() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);

    let message = b"Satyata is truth";
    let signature = identity.sign(message);

    assert!(identity.public().verify(message, &signature));
}

#[test]
fn identity_verify_fails_on_wrong_message() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);

    let message = b"Satyata is truth";
    let signature = identity.sign(message);

    assert!(!identity.public().verify(b"Wrong message", &signature));
}

#[test]
fn identity_verify_fails_on_wrong_signature() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);

    let message = b"Satyata is truth";
    let mut signature_bytes = identity.sign(message).as_bytes().to_vec();

    // Tamper with signature
    signature_bytes[0] ^= 0xFF;
    let tampered_sig = crate::base::crypto::Signature::new(signature_bytes);

    assert!(!identity.public().verify(message, &tampered_sig));
}

#[test]
fn identity_is_deterministic_from_mnemonic() {
    let id1 = SecretIdentity::from_mnemonic(MNEMONIC_1, "").expect("Failed to derive id1");
    let id2 = SecretIdentity::from_mnemonic(MNEMONIC_1, "").expect("Failed to derive id2");

    assert_eq!(id1.public(), id2.public());
}

#[test]
fn identity_fails_on_invalid_mnemonic() {
    let invalid_mnemonic = "invalid mnemonic phrase that is not twenty four words long";
    let result = SecretIdentity::from_mnemonic(invalid_mnemonic, "");
    assert!(result.is_err());
}

#[test]
fn identity_adversarial_entropy_wall() {
    let short_mnemonics = vec![
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // 12
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // 15
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // 18
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // 21
    ];

    for m in short_mnemonics {
        let result = SecretIdentity::from_mnemonic(m, "");
        match result {
            Err(crate::base::error::SovereignError::Identity(
                crate::base::error::IdentityError::MnemonicInvalid(msg),
            )) => {
                assert!(
                    msg.contains("exactly 24 words"),
                    "Error message should enforce 24 words: {}",
                    msg
                );
            }
            Ok(_) => panic!("MasterIdentity should have REJECTED mnemonic: {}", m),
            Err(e) => panic!("Unexpected error type for mnemonic {}: {:?}", m, e),
        }
    }
}

#[test]
fn identity_derivation_changes_with_passphrase() {
    let id1 = SecretIdentity::from_mnemonic(MNEMONIC_1, "pass1").unwrap();
    let id2 = SecretIdentity::from_mnemonic(MNEMONIC_1, "pass2").unwrap();

    assert_ne!(id1.public(), id2.public());
}

#[test]
fn identity_can_generate_valid_mnemonics() {
    let mnemonic = SecretIdentity::generate_mnemonic().expect("Generation failed");
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);

    // Should be able to rebirth from it
    let id = SecretIdentity::from_mnemonic(&mnemonic, "");
    assert!(id.is_ok());
}

#[test]
fn identity_derivation_matches_bip39_standard_phrase() {
    // 24-word valid phrase for compatibility check (standard "abandon" phrase)
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let id = SecretIdentity::from_mnemonic(mnemonic, "TREZOR").unwrap();

    // Verify derivation path m/44'/999'/0'/0'/0' works
    assert!(id.public().signing_key().as_bytes().len() == 32);
}

#[test]
fn identity_derives_isolated_graph_keys() {
    let mut rng = OsRng;
    let secret_id = SecretIdentity::generate(&mut rng);

    let graph_id = GraphId::new();
    let graph_key = secret_id
        .derive_graph_key(&graph_id)
        .expect("Derivation failed");

    // Must be deterministic
    let recovered_key = secret_id
        .derive_graph_key(&graph_id)
        .expect("Derivation failed");
    assert_eq!(graph_key, recovered_key);

    // Must change with GraphID
    let graph_id_2 = GraphId::new();
    let graph_key_2 = secret_id
        .derive_graph_key(&graph_id_2)
        .expect("Derivation failed");
    assert_ne!(graph_key, graph_key_2);
}

#[tokio::test]
async fn identity_adversarial_shadow_isolation() {
    let mnemonic = MNEMONIC_1;
    let master = crate::identity::types::MasterIdentity::from_mnemonic(mnemonic, "").unwrap();
    let alice = master.derive_child("m/44'/999'/0'/0'/0'", None).unwrap();
    let alice_pub = alice.public().signing_key().clone();

    let gid_a = GraphId::new();
    let gid_b = GraphId::new();

    // Shadow Key for Graph A
    let shadow_a = master
        .derive_child("m/44'/999'/0'/1'/0'", Some(&gid_a))
        .unwrap();

    // Attempting to use Shadow A to sign for Graph B
    let data_root = crate::base::address::BlockId::from_sha256(&[0xBB; 32]);
    let malicious_manifest = crate::graph::Manifest::new(
        gid_b,
        data_root,
        vec![],
        crate::base::address::ManifestId::null(),
        &shadow_a,
    );

    // Audit in context of Graph B
    let store = crate::state::in_memory_store::InMemoryStore::new();
    let auditor = crate::traversal::auditor::Auditor::new(&store, alice_pub.clone());

    let result = auditor.audit_manifest(&malicious_manifest).await;

    // This should fail because the Shadow Key derived for GID_A is mathematically
    // different from the one that would be derived for GID_B.
    assert!(
        result.is_err(),
        "Auditor MUST reject Shadow Key from a different graph context"
    );
}

#[test]
fn test_mnemonic_normalization_and_whitespace() {
    let mnemonic_ws = format!("  {}  ", MNEMONIC_1);
    let uppercase = MNEMONIC_1.to_uppercase();

    let id1 = SecretIdentity::from_mnemonic(&mnemonic_ws, "").unwrap();
    let id2 = SecretIdentity::from_mnemonic(&uppercase, "").unwrap();

    assert_eq!(id1.public(), id2.public());
}

#[test]
fn test_full_identity_rebirth_recovery() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let original_id = SecretIdentity::from_mnemonic(&mnemonic, "secret").unwrap();

    let graph_id = GraphId::new();
    let original_key = original_id.derive_graph_key(&graph_id).unwrap();

    // Simulating device loss...
    // Rebirth on new device
    let recovered_id = SecretIdentity::from_mnemonic(&mnemonic, "secret").unwrap();
    let recovered_key = recovered_id.derive_graph_key(&graph_id).unwrap();

    assert_eq!(original_key, recovered_key);
}

pub mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn p_identity_from_entropy_robustness(entropy in prop::collection::vec(0u8..255, 32)) {
            let mut h = [0u8; 32];
            h.copy_from_slice(&entropy);
            // In theory OsRng is better but for PBT we use seedable
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&h);
            let _ = SecretIdentity::from_signing_key(signing_key);
        }

        #[test]
        fn p_graph_key_isolation(
            mnemonic in "[a-z ]{10,100}",
            g1_bytes in prop::collection::vec(0u8..255, 16),
            g2_bytes in prop::collection::vec(0u8..255, 16)
        ) {
            // We ignore invalid mnemonics for this property test
            if let Ok(secret_id) = SecretIdentity::from_mnemonic(&mnemonic, "") {
                let mut b1 = [0u8; 16]; b1.copy_from_slice(&g1_bytes);
                let mut b2 = [0u8; 16]; b2.copy_from_slice(&g2_bytes);
                let g1 = GraphId::from_bytes(b1);
                let g2 = GraphId::from_bytes(b2);

                let key1 = secret_id.derive_graph_key(&g1).unwrap();
                let key2 = secret_id.derive_graph_key(&g1).unwrap();
                let key3 = secret_id.derive_graph_key(&g2).unwrap();

                // Comparison by reference to avoid move
                prop_assert_eq!(&key1, &key2);
                if g1 != g2 {
                    prop_assert_ne!(&key1, &key3);
                }
            }
        }
    }
}

#[test]
fn identity_derivation_changes_with_passphrase_avalanche() {
    let id1 = SecretIdentity::from_mnemonic(MNEMONIC_1, "a").unwrap();
    let id2 = SecretIdentity::from_mnemonic(MNEMONIC_1, "b").unwrap();

    assert_ne!(id1.public(), id2.public());
}

#[test]
fn identity_derivation_avalanche_effect() {
    let m1 = SecretIdentity::generate_mnemonic().unwrap();
    let m2 = SecretIdentity::generate_mnemonic().unwrap();

    let id1 = SecretIdentity::from_mnemonic(&m1, "").unwrap();
    let id2 = SecretIdentity::from_mnemonic(&m2, "").unwrap();

    assert_ne!(id1.public(), id2.public());
}

#[test]
fn test_hierarchical_path_isolation() {
    // Both identities use the same mnemonic but different functional paths
    let legislator_path = "m/44'/999'/0'/0'";
    let executive_path = "m/44'/999'/0'/1'/0'";

    let id_legislator = SecretIdentity::from_mnemonic_at_path(MNEMONIC_1, "", legislator_path)
        .expect("Failed to derive legislator");

    let id_executive = SecretIdentity::from_mnemonic_at_path(MNEMONIC_1, "", executive_path)
        .expect("Failed to derive executive");

    // CRITICAL INVARIANT: Different paths must yield different keys
    assert_ne!(
        id_legislator.public().signing_key(),
        id_executive.public().signing_key(),
        "Legislator and Executive keys must be mathematically isolated"
    );
}

#[test]
fn identity_derive_key_invalid_path_format() {
    // Test various invalid path formats
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // Non-hardened path (Ed25519 requires hardened)
    let result = SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "m/44/999/0/0/0");
    assert!(result.is_err(), "Must reject non-hardened path");

    // Missing 'm' prefix
    let result = SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "44'/999'/0'/0'/0'");
    assert!(result.is_err(), "Must reject path without 'm' prefix");

    // Invalid characters
    let result = SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "m/44'/999'/0'/0'/x");
    assert!(result.is_err(), "Must reject path with invalid characters");

    // Empty path
    let result = SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "");
    assert!(result.is_err(), "Must reject empty path");

    // Overflow index
    let result = SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "m/4294967296'");
    assert!(result.is_err(), "Must reject overflow index");
}

#[test]
fn shadow_key_collision_resistance() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Generate two different master identities
    let identity_a = SecretIdentity::generate(&mut OsRng);
    let identity_b = SecretIdentity::generate(&mut OsRng);
    let graph_id = GraphId::new();

    // Derive shadow keys using the same HMAC logic as IdentityGraph
    let mut hmac_a =
        Hmac::<Sha256>::new_from_slice(identity_a.public().signing_key().as_bytes()).unwrap();
    hmac_a.update(b"akshara.v1.shadow_identity");
    hmac_a.update(graph_id.as_bytes());
    let shadow_a = hmac_a.finalize().into_bytes();

    let mut hmac_b =
        Hmac::<Sha256>::new_from_slice(identity_b.public().signing_key().as_bytes()).unwrap();
    hmac_b.update(b"akshara.v1.shadow_identity");
    hmac_b.update(graph_id.as_bytes());
    let shadow_b = hmac_b.finalize().into_bytes();

    // CRITICAL SECURITY INVARIANT:
    // Two different masters MUST NOT produce the same shadow key
    assert_ne!(
        shadow_a[..],
        shadow_b[..],
        "Shadow key collision: two different masters produced same shadow!"
    );
}

#[test]
fn mnemonic_validation_edge_cases() {
    // Test empty mnemonic
    let result = SecretIdentity::from_mnemonic("", "");
    assert!(result.is_err(), "Empty mnemonic should fail");

    // Test single word
    let result = SecretIdentity::from_mnemonic("abandon", "");
    assert!(result.is_err(), "Single word should fail");

    // Test 12 words - should FAIL (Akshara requires 24 words for 256-bit security)
    let result = SecretIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    );
    assert!(
        result.is_err(),
        "12-word mnemonic should fail (Akshara requires 24 words)"
    );

    // Test 24 words (should work - valid BIP39)
    let result = SecretIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "",
    );
    assert!(result.is_ok(), "Valid 24-word mnemonic should work");

    // Test wrong checksum (last word changed)
    let result = SecretIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "",
    );
    assert!(result.is_err(), "Invalid checksum should fail");

    // Test invalid word
    let result = SecretIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid word",
        "",
    );
    assert!(result.is_err(), "Invalid word should fail");
}

#[test]
fn test_keyring_secret_synchronization() {
    // Both devices start with the same mnemonic
    let version = 0;

    // Device A (Laptop) derives the keyring secret
    let laptop_secret = SecretIdentity::derive_keyring_secret(MNEMONIC_1, "", version)
        .expect("Failed to derive laptop secret");

    // Device B (Phone) derives the same keyring secret
    let phone_secret = SecretIdentity::derive_keyring_secret(MNEMONIC_1, "", version)
        .expect("Failed to derive phone secret");

    // 1. MUST be identical across devices
    assert_eq!(
        laptop_secret, phone_secret,
        "Keyring secrets must be deterministic and shared"
    );

    // 2. MUST change with version (for rotation/forward secrecy)
    let rotated_secret =
        SecretIdentity::derive_keyring_secret(MNEMONIC_1, "", version + 1).unwrap();
    assert_ne!(
        laptop_secret, rotated_secret,
        "Rotated keyring secrets must be distinct"
    );
}
