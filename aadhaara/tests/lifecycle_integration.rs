use akshara_aadhaara::{
    Address, Block, BlockId, GraphId, GraphKey, GraphStore, Heads, InMemoryStore, IndexBuilder,
    Manifest, ManifestId, Reconciler, SecretIdentity, SovereignSigner,
};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// SCENARIO 1: Deep Tree Synchronization
///
/// Verifies that the foundation can handle the recursive push and pull
/// of a deep structure using only the public Reconciler and GraphStore.
#[tokio::test]
async fn test_sync_recursive_index_structure() {
    let mut laptop_store = InMemoryStore::new();
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let identity = SecretIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let graph_id = GraphId::new();
    let graph_key = identity.derive_graph_key(&graph_id).unwrap();

    // 1. Create a deep tree: folder/sub/file.txt
    let data = b"Target Bits".to_vec();
    let leaf = Block::new(data, "data".into(), vec![], &graph_key, &identity).unwrap();
    laptop_store.put_block(&leaf).await.unwrap();

    let mut builder = IndexBuilder::new();
    builder
        .insert("folder/sub/file.txt", Address::from(leaf.id()))
        .unwrap();
    let root_index_id = builder
        .build(&mut laptop_store, &identity, &graph_key)
        .await
        .unwrap();

    let manifest = Manifest::new(
        graph_id,
        root_index_id,
        vec![],
        ManifestId::null(),
        &identity,
    );
    laptop_store.put_manifest(&manifest).await.unwrap();

    // 2. RECURSIVE PUSH (Simulating an SDK's push engine)
    // We walk the content tree from the manifest root and push all blocks to the relay
    relay_store.put_manifest(&manifest).await.unwrap();
    sync_recursive_closure(root_index_id, &graph_key, &laptop_store, &mut relay_store).await;

    // 3. PULL on Phone
    let reconciler_phone = Reconciler::new(&relay_store, identity.public_key());
    let heads_relay = relay_store.get_heads(&graph_id).await.unwrap();

    // Turn 1: Discovery (Pulls the Manifest)
    let comp_pull = reconciler_phone
        .reconcile(&Heads::new(graph_id, heads_relay), &[])
        .await
        .unwrap();
    reconciler_phone
        .converge(&comp_pull.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    // Turn 2+: Recursive Closure Pull (Simulated SDK Automation)
    sync_recursive_closure(root_index_id, &graph_key, &relay_store, &mut phone_store).await;

    // 4. Verification: Proving the manifest and data arrived
    let restored_manifest = phone_store
        .get_manifest(&manifest.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored_manifest.id(), manifest.id());

    let restored_leaf = phone_store.get_block(&leaf.id()).await.unwrap().unwrap();
    assert_eq!(
        restored_leaf.content().decrypt(&graph_key).unwrap(),
        b"Target Bits"
    );
}

/// SCENARIO 2: Identity Rebirth
#[tokio::test]
async fn test_identity_rebirth_bootstrap() {
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let identity = SecretIdentity::from_mnemonic(&mnemonic, "salt").unwrap();
    let id_gid = GraphId::new();

    // Identity Graph uses a null key for simplicity in bootstrap
    let id_key = GraphKey::new([0u8; 32]);

    let id_root = Block::new(
        vec![],
        akshara_aadhaara::BlockType::AksharaAuthV1,
        vec![],
        &id_key,
        &identity,
    )
    .unwrap();
    let id_manifest = Manifest::new(id_gid, id_root.id(), vec![], ManifestId::null(), &identity);

    relay_store.put_block(&id_root).await.unwrap();
    relay_store.put_manifest(&id_manifest).await.unwrap();

    let reborn_identity = SecretIdentity::from_mnemonic(&mnemonic, "salt").unwrap();
    let reconciler = Reconciler::new(&relay_store, reborn_identity.public_key());

    let heads = relay_store.get_heads(&id_gid).await.unwrap();
    let comp = reconciler
        .reconcile(&Heads::new(id_gid, heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&comp.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    assert!(
        phone_store
            .get_manifest(&id_manifest.id())
            .await
            .unwrap()
            .is_some()
    );
}

/// SCENARIO 3: Full Lifecycle Smoke Test
#[tokio::test]
async fn test_full_lifecycle_smoke_test() {
    let mut laptop_store = InMemoryStore::new();
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let alice = SecretIdentity::from_mnemonic(&mnemonic, "").unwrap();

    let gid = GraphId::new();
    let gkey = alice.derive_graph_key(&gid).unwrap();
    let data = Block::new(b"bits".to_vec(), "data".into(), vec![], &gkey, &alice).unwrap();
    laptop_store.put_block(&data).await.unwrap();
    let manifest = Manifest::new(gid, data.id(), vec![], ManifestId::null(), &alice);
    laptop_store.put_manifest(&manifest).await.unwrap();

    relay_store.put_block(&data).await.unwrap();
    relay_store.put_manifest(&manifest).await.unwrap();

    let reconciler = Reconciler::new(&relay_store, alice.public_key());
    let heads = relay_store.get_heads(&gid).await.unwrap();
    let comp = reconciler
        .reconcile(&Heads::new(gid, heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&comp.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    let restored_block = phone_store.get_block(&data.id()).await.unwrap().unwrap();
    assert_eq!(restored_block.content().decrypt(&gkey).unwrap(), b"bits");
}

/// Generic recursive synchronization helper.
async fn sync_recursive_closure<S: GraphStore + ?Sized, D: GraphStore + ?Sized>(
    root_id: BlockId,
    key: &GraphKey,
    source: &S,
    dest: &mut D,
) {
    let mut queue = VecDeque::new();
    queue.push_back(root_id);
    let mut visited = HashSet::new();

    while let Some(current_id) = queue.pop_front() {
        if !visited.insert(current_id) {
            continue;
        }

        // 1. Fetch block from source and ensure it exists in dest
        if let Some(block) = source.get_block(&current_id).await.unwrap() {
            dest.put_block(&block).await.unwrap();

            // 2. If it's an index, discover and queue children
            if *block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1 {
                let plaintext = block.content().decrypt(key).unwrap();
                let index: BTreeMap<String, Address> =
                    akshara_aadhaara::from_canonical_bytes(&plaintext).unwrap();
                for addr in index.values() {
                    if let Ok(child_id) = BlockId::try_from(*addr) {
                        queue.push_back(child_id);
                    }
                }
            }
        }
    }
}
