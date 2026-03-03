use akshara_aadhaara::{
    Address, Block, BlockId, GraphId, GraphKey, GraphStore, Heads, InMemoryStore, Manifest,
    ManifestId, Reconciler, SecretIdentity,
};
use std::collections::BTreeMap;

#[tokio::test]
async fn test_full_sovereign_lifecycle_rebirth_and_sync() {
    // --- Phase 1: Alice's Initial Life ---
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice = SecretIdentity::from_mnemonic(&mnemonic, "pass").unwrap();
    let mut alice_store = InMemoryStore::new();

    // We must create a real identity genesis anchor for the Auditor to be satisfied.
    let identity_key = GraphKey::new([0u8; 32]);

    let mut devices_map = BTreeMap::new();
    let signer_hex = alice
        .public()
        .signing_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let auth_block = Block::new(
        vec![],
        "akshara.auth.v1".to_string(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&auth_block).await.unwrap();
    devices_map.insert(signer_hex, Address::from(auth_block.id()));

    let devices_index = Block::new(
        akshara_aadhaara::to_canonical_bytes(&devices_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&devices_index).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("credentials".to_string(), Address::from(devices_index.id()));

    let genesis_index = Block::new(
        akshara_aadhaara::to_canonical_bytes(&root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &identity_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&genesis_index).await.unwrap();

    let null_anchor = ManifestId::from_sha256(&[0u8; 32]);
    let genesis_manifest = Manifest::new(
        GraphId::new(),
        genesis_index.id(),
        vec![],
        null_anchor,
        &alice,
    );
    alice_store.put_manifest(&genesis_manifest).await.unwrap();
    let anchor = genesis_manifest.id();

    // Now Alice creates her project graph anchored to her identity genesis
    let graph_id = GraphId::new();
    let graph_key = alice.derive_graph_key(&graph_id).unwrap();

    let content = b"The Master Plan".to_vec();
    let data_block = Block::new(
        content.clone(),
        "document".to_string(),
        vec![],
        &graph_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&data_block).await.unwrap();

    let mut project_root_map = BTreeMap::new();
    project_root_map.insert("plan.txt".to_string(), Address::from(data_block.id()));

    let project_index_block = Block::new(
        akshara_aadhaara::to_canonical_bytes(&project_root_map).unwrap(),
        "akshara.index.v1".to_string(),
        vec![],
        &graph_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&project_index_block).await.unwrap();

    let manifest = Manifest::new(graph_id, project_index_block.id(), vec![], anchor, &alice);
    alice_store.put_manifest(&manifest).await.unwrap();

    // --- Phase 2: Total Hardware Loss ---
    drop(alice_store);

    // --- Phase 3: The Rebirth ---
    let alice_new_phone = SecretIdentity::from_mnemonic(&mnemonic, "pass").unwrap();
    let mut relay_mock_store = InMemoryStore::new();

    // Simulate synced data on Relay (Including Alice's Identity Genesis!)
    relay_mock_store.put_block(&auth_block).await.unwrap();
    relay_mock_store.put_block(&devices_index).await.unwrap();
    relay_mock_store.put_block(&genesis_index).await.unwrap();
    relay_mock_store
        .put_manifest(&genesis_manifest)
        .await
        .unwrap();

    relay_mock_store.put_block(&data_block).await.unwrap();
    relay_mock_store
        .put_block(&project_index_block)
        .await
        .unwrap();
    relay_mock_store.put_manifest(&manifest).await.unwrap();

    // --- Phase 4: Convergence (Turn 1: Discovery) ---
    let mut alice_restored_store = InMemoryStore::new();
    let reconciler = Reconciler::new(
        &relay_mock_store,
        alice_new_phone.public().signing_key().clone(),
    );

    let remote_heads = Heads::new(graph_id, vec![manifest.id()]);

    let comparison = reconciler.reconcile(&remote_heads, &[]).await.unwrap();

    // Process Turn 1 using the high-level converge utility
    let report = reconciler
        .converge(&comparison.peer_surplus, &mut alice_restored_store)
        .await
        .unwrap();
    assert!(report.manifests_synced > 0);
    // --- Phase 5: Turning the Wheel (Turn 2: Filling Gaps) ---
    let restored_manifest = alice_restored_store
        .get_manifest(&manifest.id())
        .await
        .unwrap()
        .unwrap();
    let index_block_id = restored_manifest.content_root();
    let index_block = alice_restored_store
        .get_block(&index_block_id)
        .await
        .unwrap()
        .unwrap();

    let plaintext = index_block.content().decrypt(&graph_key).unwrap();
    let index: BTreeMap<String, Address> =
        akshara_aadhaara::from_canonical_bytes(&plaintext).unwrap();
    let plan_addr = index.get("plan.txt").unwrap();

    let plan_delta = akshara_aadhaara::Delta::new(vec![*plan_addr]);
    let _report = reconciler
        .converge(&plan_delta, &mut alice_restored_store)
        .await
        .unwrap();

    // --- Phase 6: Final Verification ---
    let restored_key = alice_new_phone.derive_graph_key(&graph_id).unwrap();
    let walker = akshara_aadhaara::GraphWalker::new(
        &alice_restored_store,
        alice_new_phone.public().signing_key().clone(),
    );
    let resolved_addr = walker
        .resolve_path(index_block_id, "plan.txt", &restored_key)
        .await
        .unwrap();

    let resolved_block_id = BlockId::try_from(resolved_addr).unwrap();
    let final_block = alice_restored_store
        .get_block(&resolved_block_id)
        .await
        .unwrap()
        .unwrap();
    let final_content = final_block.content().decrypt(&restored_key).unwrap();

    assert_eq!(final_content, b"The Master Plan");
}

#[tokio::test]
async fn test_collaborative_recovery_symphony() {
    use akshara_aadhaara::{
        Address, Block, BlockId, GraphId, GraphKey, GraphStore, GraphWalker, InMemoryStore,
        IndexBuilder, Manifest, ManifestId, SecretIdentity, SovereignSigner,
    };

    let mut relay_store = InMemoryStore::new();
    let alice_mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // --- Phase 1: The Laptop (Genesis) ---
    let alice_laptop = SecretIdentity::from_mnemonic(&alice_mnemonic, "salt").unwrap();

    // Bob gives Alice a random project key (Collaborative Key)
    let bob_project_id = GraphId::new();
    let bob_project_key = GraphKey::generate(&mut rand::rngs::OsRng);

    // Alice's Laptop derive the keyring secret to 'Vault' Bob's key
    let keyring_secret = SecretIdentity::derive_keyring_secret(&alice_mnemonic, "salt", 0).unwrap();
    let keyring_key = GraphKey::new(keyring_secret);

    // 1. Create the Descriptor Block (The Leaf)
    // The key is encrypted by the keyring_key during block creation
    let descriptor = Block::new(
        bob_project_key.as_bytes().to_vec(),
        "akshara.resource.v1".into(),
        vec![],
        &keyring_key,
        &alice_laptop,
    )
    .unwrap();
    relay_store.put_block(&descriptor).await.unwrap();

    // 2. Use IndexBuilder to construct the Identity Graph hierarchy
    let mut builder = IndexBuilder::new();
    builder
        .insert(
            &format!("shared/{}", bob_project_id),
            Address::from(descriptor.id()),
        )
        .unwrap();

    let root_index_id = builder
        .build(&mut relay_store, &alice_laptop, &keyring_key)
        .await
        .unwrap();

    // Laptop pushes Identity Manifest to Relay
    let alice_id_graph = GraphId::new();
    let identity_manifest = Manifest::new(
        alice_id_graph,
        root_index_id,
        vec![],
        ManifestId::from_sha256(&[0u8; 32]),
        &alice_laptop,
    );
    relay_store.put_manifest(&identity_manifest).await.unwrap();

    // --- Phase 2: The Rebirth (New Phone) ---
    // Laptop is gone. Alice has only her words.
    let alice_phone = SecretIdentity::from_mnemonic(&alice_mnemonic, "salt").unwrap();

    // Phone reconstructs the Keyring Secret
    let recovered_keyring_secret =
        SecretIdentity::derive_keyring_secret(&alice_mnemonic, "salt", 0).unwrap();
    let recovered_keyring_key = GraphKey::new(recovered_keyring_secret);

    // Phone finds the Identity Manifest on Relay
    let heads = relay_store.get_heads(&alice_id_graph).await.unwrap();
    let latest_id_manifest = relay_store.get_manifest(&heads[0]).await.unwrap().unwrap();

    // Phone walks the graph to find the shared project
    let walker = GraphWalker::new(&relay_store, alice_phone.public_key());
    let res_addr = walker
        .resolve_path(
            latest_id_manifest.content_root(),
            &format!("shared/{}", bob_project_id),
            &recovered_keyring_key,
        )
        .await
        .unwrap();

    let descriptor_id = BlockId::try_from(res_addr).unwrap();
    let descriptor_block = relay_store
        .get_block(&descriptor_id)
        .await
        .unwrap()
        .expect("Descriptor block not found");

    // Phone decrypts the vault to recover Bob's random key!
    let decrypted_bytes = descriptor_block
        .content()
        .decrypt(&recovered_keyring_key)
        .unwrap();
    let recovered_project_key_bytes: [u8; 32] = decrypted_bytes.try_into().unwrap();
    let recovered_project_key = GraphKey::new(recovered_project_key_bytes);

    // --- Final Assertion ---
    assert_eq!(
        bob_project_key, recovered_project_key,
        "Alice must recover Bob's random key using only her words"
    );
}
