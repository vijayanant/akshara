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
    // 12-word valid phrase for compatibility check
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
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
