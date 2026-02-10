use rand::rngs::OsRng;
use sovereign_core::crypto::{Signature, SovereignSigner};
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
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let id = SecretIdentity::from_mnemonic(mnemonic, "");

    assert!(
        id.is_ok(),
        "Implementation must support standard 24-word BIP-39 phrases"
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
fn test_mnemonic_normalization_and_whitespace() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let messy_phrase = format!("  {}  ", phrase.to_uppercase());

    let id1 = SecretIdentity::from_mnemonic(phrase, "salt").unwrap();
    let id2 = SecretIdentity::from_mnemonic(&messy_phrase, "salt").unwrap();

    assert_eq!(id1.public().signing_key(), id2.public().signing_key());
}

#[test]
fn test_full_identity_rebirth_recovery() {
    use sovereign_core::graph::{Block, GraphId};

    // --- SCENARIO: Device A (The Past) ---
    let phrase = SecretIdentity::generate_mnemonic();
    let graph_id = GraphId::new();
    let id_a = SecretIdentity::from_mnemonic(&phrase, "pass").unwrap();
    let graph_key = id_a.derive_graph_key(&graph_id);

    let plaintext = b"Akshara - The Permanent Web";
    let block = Block::new(
        plaintext.to_vec(),
        "p".to_string(),
        vec![],
        &graph_key,
        &id_a,
    )
    .unwrap();

    // --- SCENARIO: Device B (The Future) ---
    // Device B has NOTHING but the mnemonic and the encrypted block.
    let id_b = SecretIdentity::from_mnemonic(&phrase, "pass").unwrap();

    // Bob re-derives the key for the graph ID
    let recovered_key = id_b.derive_graph_key(&graph_id);
    assert_eq!(
        graph_key, recovered_key,
        "Recovered key must match original"
    );

    // Bob decrypts the data
    let decrypted = block.content().decrypt(&recovered_key).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn identity_can_generate_valid_mnemonics() {
    let phrase = SecretIdentity::generate_mnemonic();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(
        words.len(),
        24,
        "Sovereign Master Seed must be 24 words for maximum security"
    );

    let id = SecretIdentity::from_mnemonic(&phrase, "");
    assert!(
        id.is_ok(),
        "Generated mnemonic must be valid for derivation"
    );
}

#[test]
fn identity_derives_isolated_graph_keys() {
    use sovereign_core::graph::GraphId;
    let mut rng = rand::thread_rng();
    let secret_id = SecretIdentity::generate(&mut rng);

    let g1 = GraphId::new();
    let g2 = GraphId::new();

    let key1 = secret_id.derive_graph_key(&g1);
    let key2 = secret_id.derive_graph_key(&g1);
    let key3 = secret_id.derive_graph_key(&g2);

    assert_eq!(key1, key2);
    assert_ne!(key1, key3);
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
    let bad_mnemonic = "abandon abandon abandon";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic, "").is_err());

    let bad_mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy";
    assert!(SecretIdentity::from_mnemonic(bad_mnemonic2, "").is_err());
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;
    use sovereign_core::graph::GraphId;

    proptest! {
        #[test]
        fn p_identity_from_entropy_robustness(ref entropy in any::<[u8; 32]>()) {
            use bip39::Mnemonic;
            let mnemonic = Mnemonic::from_entropy(entropy).unwrap();
            let phrase = mnemonic.to_string();

            let id1 = SecretIdentity::from_mnemonic(&phrase, "pass").unwrap();
            let id2 = SecretIdentity::from_mnemonic(&phrase, "pass").unwrap();

            prop_assert_eq!(id1.public().signing_key(), id2.public().signing_key());
        }

        #[test]
        fn p_graph_key_isolation(ref g1_uuid in any::<[u8; 16]>(), ref g2_uuid in any::<[u8; 16]>()) {
            let g1 = GraphId(uuid::Uuid::from_bytes(*g1_uuid));
            let g2 = GraphId(uuid::Uuid::from_bytes(*g2_uuid));

            let mut rng = rand::thread_rng();
            let secret_id = SecretIdentity::generate(&mut rng);

            let k1 = secret_id.derive_graph_key(&g1);
            let k2 = secret_id.derive_graph_key(&g2);

            if g1 != g2 {
                prop_assert_ne!(k1, k2);
            } else {
                prop_assert_eq!(k1, k2);
            }
        }
    }
}
