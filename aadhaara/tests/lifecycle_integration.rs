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
        serde_cbor::to_vec(&devices_map).unwrap(),
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
        serde_cbor::to_vec(&root_map).unwrap(),
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
        serde_cbor::to_vec(&project_root_map).unwrap(),
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
    let index: BTreeMap<String, Address> = serde_cbor::from_slice(&plaintext).unwrap();
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
