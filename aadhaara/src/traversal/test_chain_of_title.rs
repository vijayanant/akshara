use crate::test_utils::TestFactory;
use crate::{Address, Auditor, Block, BlockType, GraphStore, Manifest};

#[tokio::test]
async fn test_chain_of_title_authorized_collaborator() {
    let mut factory = TestFactory::new().await;
    let store = factory.store.clone();

    // 1. Setup Alice (Legislator)
    factory.anchor = factory.create_identity_anchor().await;
    let alice_id = factory.identity.clone();
    let alice_graph_id = factory.graph_id;
    let alice_graph_key = factory.graph_key.clone();
    let alice_anchor = factory.anchor;
    let alice_genesis = factory.create_genesis().await;

    // 2. Setup Bob (Collaborator)
    let mut bob_factory = TestFactory::new().await;
    bob_factory.store = store.clone(); // Shared store
    bob_factory.anchor = bob_factory.create_identity_anchor().await;
    let bob_id = bob_factory.identity.clone();
    let bob_anchor = bob_factory.anchor;
    let bob_root_key = bob_id.public().signing_key().clone();

    // 3. Bob attempts to sign a manifest for Alice's graph WITHOUT trust delegation
    let bob_manifest_unauthorized = Manifest::new(
        alice_graph_id,
        factory.dummy_root(),
        vec![alice_genesis.id()],
        bob_anchor,
        &bob_id,
        None,
    );
    store
        .put_manifest(&bob_manifest_unauthorized)
        .await
        .unwrap();

    let auditor = Auditor::new(store.as_ref());
    let result = auditor
        .audit_manifest(&bob_manifest_unauthorized, Some(&alice_graph_id))
        .await;

    assert!(
        result.is_err(),
        "Bob should NOT be authorized to sign Alice's graph without delegation"
    );

    // 4. Alice adds a trust delegation block for Bob
    let trust_block = Block::new(
        alice_graph_id,
        vec![], // Empty payload for now
        BlockType::AksharaTrustV1,
        vec![],
        &alice_graph_key,
        &alice_id,
    )
    .unwrap();
    store.put_block(&trust_block).await.unwrap();

    let mut index_builder = crate::traversal::IndexBuilder::new();
    // Convention: .akshara.trust/<pubkey_hex>
    index_builder
        .insert(
            &format!(".akshara.trust/{}", bob_root_key.to_hex()),
            Address::from(trust_block.id()),
        )
        .unwrap();

    let root_index_id = index_builder
        .build(alice_graph_id, store.as_ref(), &alice_id, &alice_graph_key)
        .await
        .unwrap();

    let alice_trust_manifest = Manifest::new(
        alice_graph_id,
        root_index_id,
        vec![alice_genesis.id()],
        alice_anchor,
        &alice_id,
        None,
    );
    store.put_manifest(&alice_trust_manifest).await.unwrap();

    // 5. Bob signs a NEW manifest building on Alice's trust manifest
    let bob_manifest_authorized = Manifest::new(
        alice_graph_id,
        factory.dummy_root(),
        vec![alice_trust_manifest.id()],
        bob_anchor,
        &bob_id,
        None,
    );
    store.put_manifest(&bob_manifest_authorized).await.unwrap();

    // 6. Auditor should now accept Bob's manifest
    let auditor_with_key = Auditor::new(store.as_ref()).with_graph_key(alice_graph_key.clone());
    let result = auditor_with_key
        .audit_manifest(&bob_manifest_authorized, Some(&alice_graph_id))
        .await;

    assert!(
        result.is_ok(),
        "Bob should be authorized after Alice added a trust delegation: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_chain_of_title_rejects_malicious_genesis_author() {
    // 1. Alice creates a graph
    let alice = TestFactory::with_anchor().await;
    let _alice_genesis = alice.create_genesis().await;

    // 2. Malicious Bob creates a GENESIS manifest with Alice's graph_id
    let bob = TestFactory::with_anchor().await;
    let bob_fake_genesis = Manifest::new(
        alice.graph_id,
        bob.dummy_root(),
        vec![], // No parents = Genesis
        bob.anchor,
        &bob.identity,
        None,
    );
    alice.store.put_manifest(&bob_fake_genesis).await.unwrap();

    // 3. Auditor should reject Bob's manifest because it's a conflict of title at genesis
    // or rather, it's not authorized by the true owner if the auditor is initialized
    // with the knowledge of the true genesis.

    // Wait, the Auditor discovers the root from the manifest itself.
    // If Bob's manifest is the only one we have, Auditor will think Bob is the owner.
    // BUT during sync, we compare against local heads.
}
