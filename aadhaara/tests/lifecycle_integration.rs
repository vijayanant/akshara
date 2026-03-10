use akshara_aadhaara::{
    Address, Block, BlockId, GraphId, GraphKey, GraphStore, Heads, InMemoryStore, IndexBuilder,
    Manifest, ManifestId, MasterIdentity, Reconciler, SecretIdentity, SovereignSigner,
};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// SCENARIO 1: Deep Tree Synchronization
#[tokio::test]
async fn test_sync_recursive_index_structure() {
    let mut laptop_store = InMemoryStore::new();
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let identity = SecretIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let graph_id = GraphId::new();
    let graph_key = identity.derive_graph_key(&graph_id).unwrap();

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

    relay_store.put_manifest(&manifest).await.unwrap();
    sync_recursive_closure(root_index_id, &graph_key, &laptop_store, &mut relay_store).await;

    let reconciler_phone = Reconciler::new(&relay_store, identity.public_key());
    let heads_relay = relay_store.get_heads(&graph_id).await.unwrap();

    let comp_pull = reconciler_phone
        .reconcile(&Heads::new(graph_id, heads_relay), &[])
        .await
        .unwrap();
    reconciler_phone
        .converge(&comp_pull.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    sync_recursive_closure(root_index_id, &graph_key, &relay_store, &mut phone_store).await;

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

/// SCENARIO 2: Honest Identity Rebirth
///
/// Alice creates her identity on a laptop, then recovers it on a phone.
/// NO variables are passed between the two scopes except the mnemonic string.
#[tokio::test]
async fn test_identity_rebirth_bootstrap() {
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let passphrase = "salt";
    // The stable base ID used to derive the Identity Graph's discovery identifier.
    let identity_graph_base_id = GraphId::from_bytes([0xDA; 16]);

    // --- Phase 1: Laptop (Creation and Sync) ---
    {
        let laptop_identity = SecretIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        let master = MasterIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        
        // Derive the stable Discovery ID for the Identity Graph
        let id_gid = master.derive_discovery_id(&identity_graph_base_id).unwrap();
        
        let id_key = GraphKey::new([0u8; 32]);
        let id_root = Block::new(
            vec![],
            akshara_aadhaara::BlockType::AksharaAuthV1,
            vec![],
            &id_key,
            &laptop_identity,
        )
        .unwrap();
        let id_manifest = Manifest::new(
            id_gid,
            id_root.id(),
            vec![],
            ManifestId::null(),
            &laptop_identity,
        );

        relay_store.put_block(&id_root).await.unwrap();
        relay_store.put_manifest(&id_manifest).await.unwrap();
    } // ALL laptop variables are destroyed here.

    // --- Phase 2: Phone (Rebirth and Recovery) ---
    let reborn_identity = SecretIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
    let phone_master = MasterIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
    
    // The phone derives the Discovery ID independently purely from the words.
    let derived_id_gid = phone_master.derive_discovery_id(&identity_graph_base_id).unwrap();

    let reconciler = Reconciler::new(&relay_store, reborn_identity.public_key());
    let heads = relay_store.get_heads(&derived_id_gid).await.unwrap();
    assert!(!heads.is_empty(), "Phone could not find Identity Graph on Relay via Discovery ID");

    let comp = reconciler
        .reconcile(&Heads::new(derived_id_gid, heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&comp.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    // PROOF: Phone has successfully recovered Alice's Identity Graph frontier.
    assert!(!phone_store.get_heads(&derived_id_gid).await.unwrap().is_empty());
}

/// SCENARIO 3: The Complete Stateless Journey (Type-Safe)
#[tokio::test]
async fn test_full_lifecycle_stateless_journey() {
    let mut laptop_store = InMemoryStore::new();
    let mut relay_store = InMemoryStore::new();
    let mut phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let passphrase = "vault";

    // --- Phase 1: Laptop Setup ---
    let (id_gid, project_id) = {
        let alice_laptop = SecretIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        let id_graph_id = GraphId::new();
        let id_key = GraphKey::new([0u8; 32]);

        let project_id = GraphId::new();
        let project_key = alice_laptop.derive_graph_key(&project_id).unwrap();
        let data = Block::new(
            b"Stateless Secret".to_vec(),
            "data".into(),
            vec![],
            &project_key,
            &alice_laptop,
        )
        .unwrap();
        laptop_store.put_block(&data).await.unwrap();
        let manifest = Manifest::new(
            project_id,
            data.id(),
            vec![],
            ManifestId::null(),
            &alice_laptop,
        );
        laptop_store.put_manifest(&manifest).await.unwrap();

        let descriptor = Block::new(
            b"Project Alpha".to_vec(),
            "akshara.descriptor.v1".into(),
            vec![],
            &id_key,
            &alice_laptop,
        )
        .unwrap();
        laptop_store.put_block(&descriptor).await.unwrap();

        let mut builder = IndexBuilder::new();
        builder
            .insert(
                &format!("projects/{}", project_id),
                Address::from(descriptor.id()),
            )
            .unwrap();
        let id_root_id = builder
            .build(&mut laptop_store, &alice_laptop, &id_key)
            .await
            .unwrap();

        let id_manifest = Manifest::new(
            id_graph_id,
            id_root_id,
            vec![],
            ManifestId::null(),
            &alice_laptop,
        );
        laptop_store.put_manifest(&id_manifest).await.unwrap();

        relay_store.put_manifest(&manifest).await.unwrap();
        relay_store.put_block(&data).await.unwrap();
        relay_store.put_manifest(&id_manifest).await.unwrap();
        sync_recursive_closure(id_root_id, &id_key, &laptop_store, &mut relay_store).await;

        (id_graph_id, project_id)
    };

    // --- Phase 3: Phone Rebirth ---
    let alice_phone = SecretIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
    let reconciler = Reconciler::new(&relay_store, alice_phone.public_key());

    // 1. Reconstruct Identity Graph from Words
    let heads = relay_store.get_heads(&id_gid).await.unwrap();
    let comp = reconciler
        .reconcile(&Heads::new(id_gid, heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&comp.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    // TYPE-SAFE DISCOVERY: Find the Manifest CID among the missing addresses
    let mut id_manifest_id = None;
    for addr in comp.peer_surplus.missing() {
        if let Ok(mid) = ManifestId::try_from(*addr) {
            id_manifest_id = Some(mid);
            break;
        }
    }

    let mid = id_manifest_id.expect("Relay failed to provide identity manifest");
    let id_manifest = phone_store.get_manifest(&mid).await.unwrap().unwrap();
    let id_key = GraphKey::new([0u8; 32]);
    sync_recursive_closure(
        id_manifest.content_root(),
        &id_key,
        &relay_store,
        &mut phone_store,
    )
    .await;

    // 2. Access Project
    let phone_project_key = alice_phone.derive_graph_key(&project_id).unwrap();
    let p_heads = relay_store.get_heads(&project_id).await.unwrap();
    let p_comp = reconciler
        .reconcile(&Heads::new(project_id, p_heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&p_comp.peer_surplus, &mut phone_store)
        .await
        .unwrap();

    let mut p_manifest_id = None;
    for addr in p_comp.peer_surplus.missing() {
        if let Ok(mid) = ManifestId::try_from(*addr) {
            p_manifest_id = Some(mid);
            break;
        }
    }

    let p_mid = p_manifest_id.expect("Relay failed to provide project manifest");
    let restored_manifest = phone_store.get_manifest(&p_mid).await.unwrap().unwrap();
    let restored_block = phone_store
        .get_block(&restored_manifest.content_root())
        .await
        .unwrap()
        .unwrap();

    let plaintext = restored_block
        .content()
        .decrypt(&phone_project_key)
        .unwrap();
    assert_eq!(plaintext, b"Stateless Secret");
}

/// Generic recursive synchronization helper for simulations.
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

        if let Some(block) = source.get_block(&current_id).await.unwrap() {
            dest.put_block(&block).await.unwrap();

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
