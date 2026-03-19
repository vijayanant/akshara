use crate::identity::SecretIdentity;
use crate::identity::types::MasterIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;

#[tokio::test]
async fn test_prekey_storage_and_consumption() {
    let mut store = InMemoryStore::new();
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();

    // 1. Create a bundle of 5 keys
    let bundle = master.generate_pre_key_bundle(0, 0, 5).unwrap();
    let device_key = bundle.device_identity.signing_key().clone();

    store.put_prekey_bundle(&bundle).await.unwrap();

    // 2. Fetch and verify
    let retrieved = store.get_prekey_bundle(&device_key).await.unwrap().unwrap();
    assert_eq!(retrieved.pre_keys.len(), 5);

    // 3. Consume index #2
    let key_2 = store.consume_prekey(&device_key, 2).await.unwrap();
    assert!(key_2.is_some());

    // 4. THE ATOMIC TEST: Try to consume #2 again
    let key_2_again = store.consume_prekey(&device_key, 2).await.unwrap();
    assert!(key_2_again.is_none(), "One-time key must not be reusable");

    // 5. Verify the rest of the bundle is intact but #2 is gone
    let final_bundle = store.get_prekey_bundle(&device_key).await.unwrap().unwrap();
    assert_eq!(final_bundle.pre_keys.len(), 4);
    assert!(!final_bundle.pre_keys.contains_key(&2));
    assert!(final_bundle.pre_keys.contains_key(&0));
}

#[tokio::test]
async fn test_prekey_reuse_attack_prevention() {
    let mut store = InMemoryStore::new();
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();

    let bundle = master.generate_pre_key_bundle(0, 0, 3).unwrap();
    let device_key = bundle.device_identity.signing_key().clone();

    store.put_prekey_bundle(&bundle).await.unwrap();

    // Attacker captures prekey at index 0
    let captured_prekey = store.consume_prekey(&device_key, 0).await.unwrap();
    assert!(
        captured_prekey.is_some(),
        "First consumption should succeed"
    );

    // Attacker tries to reuse the same prekey (replay attack)
    let reused_prekey = store.consume_prekey(&device_key, 0).await.unwrap();

    // CRITICAL SECURITY INVARIANT:
    // Pre-keys MUST be one-time use only - prevents replay attacks
    assert!(
        reused_prekey.is_none(),
        "Pre-key reuse attack succeeded! Same prekey returned twice!"
    );
}
