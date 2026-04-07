use akshara_aadhaara::{
    Address, Block, BlockContent, BlockId, GraphDescriptor, GraphId, GraphKey, GraphStore, Heads,
    IdentityGraph, InMemoryStore, IndexBuilder, Manifest, ManifestId, MasterIdentity, Reconciler,
    SecretIdentity,
};
use rand::RngCore;
use rand::rngs::OsRng;

use std::collections::{BTreeMap, HashSet, VecDeque};

/// SCENARIO 1: Deep Tree Synchronization
#[tokio::test]
async fn test_sync_recursive_index_structure() {
    let laptop_store = InMemoryStore::new();
    let relay_store = InMemoryStore::new();
    let phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let identity = SecretIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let graph_id = GraphId::new();
    let graph_key = identity.derive_graph_key(&graph_id).unwrap();

    let data = b"Target Bits".to_vec();
    let leaf = Block::new(
        graph_id,
        data,
        akshara_aadhaara::BlockType::AksharaDataV1,
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();
    laptop_store.put_block(&leaf).await.unwrap();

    let mut builder = IndexBuilder::new();
    builder
        .insert("folder/sub/file.txt", Address::from(leaf.id()))
        .unwrap();
    let root_index_id: akshara_aadhaara::BlockId = builder
        .build(graph_id, &laptop_store, &identity, &graph_key)
        .await
        .unwrap();

    let manifest = Manifest::new(
        graph_id,
        leaf.id(),
        vec![],
        ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );

    laptop_store.put_manifest(&manifest).await.unwrap();

    relay_store.put_manifest(&manifest).await.unwrap();
    sync_recursive_closure(
        &graph_id,
        root_index_id,
        &graph_key,
        &laptop_store,
        &relay_store,
    )
    .await;

    let reconciler_phone = Reconciler::new(&relay_store);
    let heads_relay = relay_store.get_heads(&graph_id).await.unwrap();

    let comp_pull = reconciler_phone
        .reconcile(&Heads::new(graph_id, heads_relay), &[])
        .await
        .unwrap();
    reconciler_phone
        .converge(&comp_pull.peer_surplus, &phone_store)
        .await
        .unwrap();

    sync_recursive_closure(
        &graph_id,
        root_index_id,
        &graph_key,
        &relay_store,
        &phone_store,
    )
    .await;

    let restored_manifest = phone_store
        .get_manifest(&manifest.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored_manifest.id(), manifest.id());

    let restored_leaf = phone_store.get_block(&leaf.id()).await.unwrap().unwrap();
    assert_eq!(
        restored_leaf.decrypt(&graph_id, &graph_key).unwrap(),
        b"Target Bits"
    );
}

/// SCENARIO 2: Honest Identity Rebirth
///
/// Alice creates her identity on a laptop, then recovers it on a phone.
/// NO variables are passed between the two scopes except the mnemonic string.
#[tokio::test]
async fn test_identity_rebirth_bootstrap() {
    let relay_store = InMemoryStore::new();
    let phone_store = InMemoryStore::new();

    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let passphrase = "salt";

    // --- Phase 1: Laptop (Creation and Sync) ---
    let identity_id = {
        let laptop_identity = SecretIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        let master = MasterIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        let id_gid = master.identity_id().unwrap();

        let id_key = akshara_aadhaara::IDENTITY_GRAPH_KEY;
        let id_root = Block::new(
            id_gid,
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
            Address::null(),
            &laptop_identity,
            None,
        );

        relay_store.put_block(&id_root).await.unwrap();
        relay_store.put_manifest(&id_manifest).await.unwrap();
        id_gid
    }; // ALL laptop variables are destroyed here.

    // --- Phase 2: Phone (Rebirth and Recovery) ---
    let phone_master = MasterIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();

    // The phone derives the Identity ID independently purely from the words.
    let derived_id_gid = phone_master.identity_id().unwrap();
    assert_eq!(derived_id_gid, identity_id);

    let reconciler = Reconciler::new(&relay_store);
    let heads = relay_store.get_heads(&derived_id_gid).await.unwrap();
    assert!(
        !heads.is_empty(),
        "Phone could not find Identity Graph on Relay via Identity ID"
    );

    let comp = reconciler
        .reconcile(&Heads::new(derived_id_gid, heads), &[])
        .await
        .unwrap();
    reconciler
        .converge(&comp.peer_surplus, &phone_store)
        .await
        .unwrap();

    // PROOF: Phone has successfully recovered Alice's Identity Graph frontier.
    assert!(
        !phone_store
            .get_heads(&derived_id_gid)
            .await
            .unwrap()
            .is_empty()
    );
}

/// SCENARIO 3: The Complete Stateless Journey (Type-Safe)
#[tokio::test]
async fn test_full_lifecycle_stateless_journey() {
    let mut rng = OsRng;
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let relay_store = InMemoryStore::new();

    // --- STEP 1: BIRTH (Alice sets up her world on Laptop) ---
    let (identity_id, _identity_lakshana) = {
        let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();
        let id_gid = master.identity_id().unwrap();
        let id_lak = master.derive_identity_lakshana().unwrap();
        let laptop_identity = master.derive_child("m/44'/999'/0'/0'/0'", None).unwrap();

        // Alice creates a private project graph
        let project_id = GraphId::new();
        let project_key_bytes = *master
            .derive_child("m/44'/999'/0'/2'/0'", Some(&project_id))
            .unwrap()
            .public()
            .encryption_key()
            .as_bytes();
        let project_key = GraphKey::new(project_key_bytes);

        // Alice registers the project in her Identity Graph (Resource Index)
        let keyring_secret = master.derive_keyring_secret(0).unwrap();
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let enc_graph_key = BlockContent::encrypt(
            project_key.as_bytes(),
            &keyring_secret,
            nonce,
            project_id.as_bytes(),
        )
        .unwrap();

        let descriptor = GraphDescriptor {
            graph_id: project_id,
            label: Some("Alice's Secret Project".to_string()),
            enc_graph_key,
            keyring_version: 0,
            created_at: 0,
            shared_by: None,
        };

        let identity_graph = IdentityGraph::new(&relay_store);
        identity_graph
            .add_resource(descriptor, true, &id_gid, &laptop_identity)
            .await
            .unwrap();

        // Alice also adds some data to the project
        let data = Block::new(
            project_id,
            b"Stateless Recovery Truth".to_vec(),
            akshara_aadhaara::BlockType::AksharaDataV1,
            vec![],
            &project_key,
            &laptop_identity.derive_shadow_identity(&project_id).unwrap(),
        )
        .unwrap();
        let manifest = Manifest::new(
            project_id,
            data.id(),
            vec![],
            ManifestId::null(),
            Address::null(),
            &laptop_identity.derive_shadow_identity(&project_id).unwrap(),
            None,
        );

        relay_store.put_block(&data).await.unwrap();
        relay_store.put_manifest(&manifest).await.unwrap();

        (id_gid, id_lak)
    };

    // --- STEP 2: LOSS (Laptop destroyed) ---
    // All local variables are gone. Only `mnemonic` and `relay_store` remain.

    // --- STEP 3: REBIRTH (Alice gets a new Phone) ---
    {
        let master = MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();
        let recovered_id_gid = master.identity_id().unwrap();

        assert_eq!(recovered_id_gid, identity_id);

        // Phone finds Identity Graph on Relay
        let heads = relay_store.get_heads(&recovered_id_gid).await.unwrap();
        let identity_graph = IdentityGraph::new(&relay_store);

        // Alice recovers her resources
        let keyring_secret = master.derive_keyring_secret(0).unwrap();
        let resources = identity_graph.list_resources(&heads[0]).await.unwrap();

        assert_eq!(resources.len(), 1);
        let (_addr, descriptor) = &resources[0];
        assert_eq!(descriptor.label.as_deref(), Some("Alice's Secret Project"));

        // Alice recovers the project key
        let project_key_bytes = descriptor
            .enc_graph_key
            .decrypt(&keyring_secret, descriptor.graph_id.as_bytes())
            .unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&project_key_bytes);
        let recovered_project_key = GraphKey::new(key_array);

        // Alice can now sync and read her project
        let project_heads = relay_store.get_heads(&descriptor.graph_id).await.unwrap();
        let project_manifest = relay_store
            .get_manifest(&project_heads[0])
            .await
            .unwrap()
            .unwrap();

        let block_id = project_manifest.content_root();
        let block = relay_store.get_block(&block_id).await.unwrap().unwrap();
        let plaintext = block
            .decrypt(&descriptor.graph_id, &recovered_project_key)
            .unwrap();

        assert_eq!(plaintext, b"Stateless Recovery Truth");
    }
}

/// Generic recursive synchronization helper for simulations.
async fn sync_recursive_closure<S: GraphStore + ?Sized, D: GraphStore + ?Sized>(
    graph_id: &GraphId,
    root_id: BlockId,
    key: &GraphKey,
    source: &S,
    dest: &D,
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
                let plaintext = block.decrypt(graph_id, key).unwrap_or_default();
                if plaintext.is_empty() {
                    continue;
                } // handle gracefully
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
