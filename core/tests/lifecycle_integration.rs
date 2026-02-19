use sovereign_core::{
    Address, Block, BlockId, GraphId, GraphStore, Heads, InMemoryStore, Manifest, ManifestId,
    Reconciler, SecretIdentity,
};
use std::collections::BTreeMap;

#[test]
fn test_full_sovereign_lifecycle_rebirth_and_sync() {
    // --- Phase 1: Alice's Initial Life ---
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice = SecretIdentity::from_mnemonic(&mnemonic, "pass").unwrap();
    let mut alice_store = InMemoryStore::new();

    let graph_id = GraphId::new();
    let graph_key = alice.derive_graph_key(&graph_id).unwrap();
    let anchor = ManifestId::from_sha256(&[0u8; 32]);

    let content = b"The Master Plan".to_vec();
    let data_block = Block::new(
        content.clone(),
        "document".to_string(),
        vec![],
        &graph_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&data_block).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("plan.txt".to_string(), Address::from(data_block.id()));
    let index_block = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".to_string(),
        vec![],
        &graph_key,
        &alice,
    )
    .unwrap();
    alice_store.put_block(&index_block).unwrap();

    let manifest = Manifest::new(graph_id, index_block.id(), vec![], anchor, &alice);
    alice_store.put_manifest(&manifest).unwrap();

    // --- Phase 2: Total Hardware Loss ---
    drop(alice_store);

    // --- Phase 3: The Rebirth ---
    let alice_new_phone = SecretIdentity::from_mnemonic(&mnemonic, "pass").unwrap();
    let mut relay_mock_store = InMemoryStore::new();

    // Simulate synced data on Relay
    relay_mock_store.put_block(&data_block).unwrap();
    relay_mock_store.put_block(&index_block).unwrap();
    relay_mock_store.put_manifest(&manifest).unwrap();

    // --- Phase 4: Convergence (Turn 1: Discovery) ---
    let mut alice_restored_store = InMemoryStore::new();
    let reconciler = Reconciler::new(&relay_mock_store);

    let remote_heads = Heads::new(graph_id, vec![manifest.id()]);

    let comparison = reconciler.reconcile(&remote_heads, &[]).unwrap();

    // Process Turn 1 using the high-level converge utility
    reconciler
        .converge(&comparison.peer_surplus, &mut alice_restored_store)
        .unwrap();

    // --- Phase 5: Turning the Wheel (Turn 2: Filling Gaps) ---
    // Now Alice can open the Index, and she realizes she is missing "plan.txt"
    let restored_manifest = alice_restored_store
        .get_manifest(&manifest.id())
        .unwrap()
        .unwrap();
    let index_block_id = restored_manifest.content_root();
    let index_block = alice_restored_store
        .get_block(&index_block_id)
        .unwrap()
        .unwrap();

    let plaintext = index_block.content().decrypt(&graph_key).unwrap();
    let index: BTreeMap<String, Address> = serde_cbor::from_slice(&plaintext).unwrap();
    let plan_addr = index.get("plan.txt").unwrap();

    // Alice reconciles AGAIN, but this time she provides her known addresses
    // Note: The Reconciler usually works on Heads, but for "Point Filling"
    // the SDK just requests the specific missing Address.

    // In our Blind Pipe model, we can just fulfill a Delta containing the missing address
    let plan_delta = sovereign_core::Delta::new(vec![*plan_addr]);
    reconciler
        .converge(&plan_delta, &mut alice_restored_store)
        .unwrap();

    // --- Phase 6: Final Verification ---
    let restored_key = alice_new_phone.derive_graph_key(&graph_id).unwrap();
    let walker = sovereign_core::GraphWalker::new(&alice_restored_store);
    let resolved_addr = walker
        .resolve_path(index_block_id, "plan.txt", &restored_key)
        .unwrap();

    let resolved_block_id = BlockId::try_from(resolved_addr).unwrap();
    let final_block = alice_restored_store
        .get_block(&resolved_block_id)
        .unwrap()
        .unwrap();
    let final_content = final_block.content().decrypt(&restored_key).unwrap();

    assert_eq!(final_content, b"The Master Plan");
}
