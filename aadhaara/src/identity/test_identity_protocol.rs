use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, BlockType, Manifest};
use crate::identity::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;

use crate::identity::types::MasterIdentity;

#[test]
fn test_akshara_blind_discovery_derivation() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let graph_id_1 = GraphId::new();
    let graph_id_2 = GraphId::new();

    // 1. First Device (Laptop) derives Discovery ID
    let discovery_id_laptop = {
        let master = MasterIdentity::from_mnemonic(&mnemonic, "salt").unwrap();
        master
            .derive_discovery_id(&graph_id_1)
            .expect("Derivation failed")
    };

    // 2. Second Device (Phone) derives Discovery ID from same words
    let discovery_id_phone = {
        let master = MasterIdentity::from_mnemonic(&mnemonic, "salt").unwrap();
        master
            .derive_discovery_id(&graph_id_1)
            .expect("Derivation failed")
    };

    // PROOF OF STATELESSNESS: Must be identical across different device objects
    assert_eq!(discovery_id_laptop, discovery_id_phone);

    // 3. Different Graph must yield different Discovery ID
    let discovery_id_other_graph = {
        let master = MasterIdentity::from_mnemonic(&mnemonic, "salt").unwrap();
        master
            .derive_discovery_id(&graph_id_2)
            .expect("Derivation failed")
    };

    // PROOF OF ISOLATION: Relay cannot link Graph 1 and Graph 2 to the same user
    assert_ne!(discovery_id_laptop, discovery_id_other_graph);
}

#[tokio::test]
async fn test_akshara_full_authority_chain_verification() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let passphrase = "pass";
    let mut relay_store = InMemoryStore::new();

    // --- ACTOR 1: Alice's Laptop (The Authorizer) ---
    let (id_root_index, alice_master_pub, id_graph_id) = {
        let alice_master =
            SecretIdentity::from_mnemonic_at_path(&mnemonic, passphrase, "m/44'/999'/0'/0'/0'")
                .unwrap();
        let alice_pub = alice_master.public().signing_key().clone();
        let graph_key = GraphKey::new([0u8; 32]);
        let id_graph_id = GraphId::new();

        // 1. Authorize a Phone (m/1'/0')
        let alice_phone_master = MasterIdentity::from_mnemonic(&mnemonic, passphrase).unwrap();
        let alice_phone = alice_phone_master
            .derive_child("m/44'/999'/0'/1'/0'", None)
            .unwrap();
        let phone_pub = alice_phone.public().signing_key().clone();

        let auth_block = Block::new(
            id_graph_id,
            phone_pub.as_bytes().to_vec(),
            BlockType::AksharaAuthV1,
            vec![],
            &graph_key,
            &alice_master,
        )
        .unwrap();
        relay_store.put_block(&auth_block).await.unwrap();

        let mut builder = crate::traversal::IndexBuilder::new();
        builder
            .insert(
                &format!("credentials/{}", phone_pub.to_hex()),
                Address::from(auth_block.id()),
            )
            .unwrap();
        let root_index_id = builder
            .build(id_graph_id, &mut relay_store, &alice_master, &graph_key)
            .await
            .unwrap();

        (root_index_id, alice_pub, id_graph_id)
    };

    // --- ACTOR 2: Alice's Phone (The Signer) ---
    // The phone creates a data update. It ONLY knows its own key and the GID.
    let (_graph_id, doc_manifest) = {
        let alice_phone =
            SecretIdentity::from_mnemonic_at_path(&mnemonic, passphrase, "m/44'/999'/0'/1'/0'")
                .unwrap();
        let gid = GraphId::new();
        let doc_root = BlockId::from_sha256(&[0xAA; 32]);

        // The phone signs the update, anchoring it to the identity graph
        let manifest = Manifest::new(gid, doc_root, vec![], ManifestId::null(), &alice_phone);
        (gid, manifest)
    };

    // --- ACTOR 3: The Relay/Auditor (The Verifier) ---
    // The Auditor has ZERO knowledge of Alice's mnemonic or private keys.
    // It only has the Relay store, the Manifest, and Alice's Master Public Key.
    {
        let walker = GraphWalker::new(&relay_store, alice_master_pub.clone());
        let identity_key = GraphKey::new([0u8; 32]);

        // 1. Walk the graph to find the authorized key
        let path = format!("/credentials/{}", doc_manifest.author().to_hex());
        let resolved_addr = walker
            .resolve_path(&id_graph_id, id_root_index, &path, &identity_key)
            .await
            .unwrap();

        let block = relay_store
            .get_block(&BlockId::try_from(resolved_addr).unwrap())
            .await
            .unwrap()
            .unwrap();
        let authorized_key_bytes = block.decrypt(&id_graph_id, &identity_key).unwrap();

        // 2. Verify: Does the key in the Identity Graph match the Signer?
        assert_eq!(authorized_key_bytes, doc_manifest.author().as_bytes());

        // 3. Verify: Is the manifest itself mathematically sound?
        doc_manifest
            .verify_integrity()
            .expect("Manifest integrity failed");
    }
}
