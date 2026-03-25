use crate::{
    Address, AksharaError, Block, BlockType, GraphId, GraphKey, GraphStore, InMemoryStore,
    IntegrityError, Manifest, ManifestId, SecretIdentity, identity::IdentityGraph,
    traversal::IndexBuilder,
};

/// Helper: Create credential block
async fn create_credential_block(
    store: &InMemoryStore,
    graph_id: GraphId,
    identity_key: &GraphKey,
    signer: &SecretIdentity,
) -> crate::BlockId {
    let auth_block = Block::new(
        graph_id,
        vec![],
        BlockType::AksharaAuthV1,
        vec![],
        identity_key,
        signer,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();
    auth_block.id()
}

/// Helper: Create Identity Graph with credentials
async fn create_identity_graph(store: &InMemoryStore, identity: &SecretIdentity) -> Manifest {
    let graph_id = GraphId::new();
    let identity_key = GraphKey::new([0u8; 32]);
    let signer_hex = identity.public().signing_key().to_hex();

    let auth_block = create_credential_block(store, graph_id, &identity_key, identity).await;

    let mut builder = IndexBuilder::new();
    builder
        .insert(
            &format!("credentials/{}", signer_hex),
            Address::from(auth_block),
        )
        .unwrap();

    let root_index_id = builder
        .build(graph_id, store, identity, &identity_key)
        .await
        .unwrap();

    let manifest = Manifest::new(
        graph_id,
        root_index_id,
        vec![],
        ManifestId::null(),
        identity,
    );
    store.put_manifest(&manifest).await.unwrap();
    manifest
}

/// Helper: Create revocation block
async fn create_revocation_block(
    store: &InMemoryStore,
    graph_id: GraphId,
    identity_key: &GraphKey,
    signer: &SecretIdentity,
) -> crate::BlockId {
    let revocation_block = Block::new(
        graph_id,
        vec![],
        BlockType::AksharaRevocationV1,
        vec![],
        identity_key,
        signer,
    )
    .unwrap();
    store.put_block(&revocation_block).await.unwrap();
    revocation_block.id()
}

// ============================================================================
// IDENTITYGRAPH AUTHORITY TESTS
// ============================================================================

#[tokio::test]
async fn test_identity_graph_verify_authority_valid() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();

    let manifest = create_identity_graph(&store, &identity).await;
    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(&master_pubkey, &manifest.id(), &master_pubkey, None)
        .await;

    assert!(result.is_ok(), "Valid authority should pass: {:?}", result);
}

#[tokio::test]
async fn test_identity_graph_genesis_accepts_master_key() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(&master_pubkey, &ManifestId::null(), &master_pubkey, None)
        .await;

    assert!(result.is_ok(), "Genesis with master key should pass");
}

#[tokio::test]
async fn test_identity_graph_genesis_rejects_wrong_key() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let wrong_identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(
            wrong_identity.public().signing_key(),
            &ManifestId::null(),
            &master_pubkey,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::UnauthorizedSigner(_))
    ));
}

#[tokio::test]
async fn test_identity_graph_missing_anchor() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let fake_anchor = ManifestId::from_sha256(&[0xAA; 32]);
    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(&master_pubkey, &fake_anchor, &master_pubkey, None)
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AksharaError::Store(_)));
}

#[tokio::test]
async fn test_identity_graph_with_latest_identity_valid() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();

    let manifest_v1 = create_identity_graph(&store, &identity).await;
    let manifest_v2 = create_identity_graph(&store, &identity).await;

    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(
            &master_pubkey,
            &manifest_v1.id(),
            &master_pubkey,
            Some(&manifest_v2.id()),
        )
        .await;

    assert!(
        result.is_ok(),
        "Valid at both anchor and latest should pass"
    );
}

#[tokio::test]
async fn test_identity_graph_ghost_branch_prevention() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let graph_id = GraphId::new();
    let identity_key = GraphKey::new([0u8; 32]);

    let signer_hex = identity.public().signing_key().to_hex();
    let auth_block = create_credential_block(&store, graph_id, &identity_key, &identity).await;

    let mut builder_v1 = IndexBuilder::new();
    builder_v1
        .insert(
            &format!("credentials/{}", signer_hex),
            Address::from(auth_block),
        )
        .unwrap();

    let root_v1 = builder_v1
        .build(graph_id, &store, &identity, &identity_key)
        .await
        .unwrap();
    let manifest_v1 = Manifest::new(graph_id, root_v1, vec![], ManifestId::null(), &identity);
    store.put_manifest(&manifest_v1).await.unwrap();

    let revocation_block =
        create_revocation_block(&store, graph_id, &identity_key, &identity).await;

    let mut builder_v2 = IndexBuilder::new();
    builder_v2
        .insert(
            &format!("revocations/{}", signer_hex),
            Address::from(revocation_block),
        )
        .unwrap();

    let root_v2 = builder_v2
        .build(graph_id, &store, &identity, &identity_key)
        .await
        .unwrap();
    let manifest_v2 = Manifest::new(
        graph_id,
        root_v2,
        vec![manifest_v1.id()],
        manifest_v1.id(),
        &identity,
    );
    store.put_manifest(&manifest_v2).await.unwrap();

    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(
            &master_pubkey,
            &manifest_v1.id(),
            &master_pubkey,
            Some(&manifest_v2.id()),
        )
        .await;

    assert!(
        result.is_err(),
        "Revoked key at latest should fail (Ghost Branch prevention)"
    );
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::UnauthorizedSigner(_))
    ));
}

#[tokio::test]
async fn test_identity_graph_revocation_scenario() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let graph_id = GraphId::new();
    let identity_key = GraphKey::new([0u8; 32]);

    let signer_hex = identity.public().signing_key().to_hex();
    let auth_block = create_credential_block(&store, graph_id, &identity_key, &identity).await;

    let mut builder_v1 = IndexBuilder::new();
    builder_v1
        .insert(
            &format!("credentials/{}", signer_hex),
            Address::from(auth_block),
        )
        .unwrap();

    let root_v1 = builder_v1
        .build(graph_id, &store, &identity, &identity_key)
        .await
        .unwrap();
    let manifest_v1 = Manifest::new(graph_id, root_v1, vec![], ManifestId::null(), &identity);
    store.put_manifest(&manifest_v1).await.unwrap();

    let revocation_block_id =
        create_revocation_block(&store, graph_id, &identity_key, &identity).await;
    let _revocation_addr = Address::from(revocation_block_id);

    let mut builder_v2 = IndexBuilder::new();
    builder_v2
        .insert(
            &format!("revocations/{}", signer_hex),
            Address::from(revocation_block_id),
        )
        .unwrap();

    let root_v2 = builder_v2
        .build(graph_id, &store, &identity, &identity_key)
        .await
        .unwrap();
    let manifest_v2 = Manifest::new(
        graph_id,
        root_v2,
        vec![manifest_v1.id()],
        manifest_v1.id(),
        &identity,
    );
    store.put_manifest(&manifest_v2).await.unwrap();

    let identity_graph = IdentityGraph::new(&store);

    let result = identity_graph
        .verify_authority(
            &master_pubkey,
            &manifest_v1.id(),
            &master_pubkey,
            Some(&manifest_v2.id()),
        )
        .await;

    assert!(
        result.is_err(),
        "Revoked key at latest should fail (Ghost Branch prevention)"
    );
}
