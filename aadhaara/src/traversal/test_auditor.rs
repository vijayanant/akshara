use crate::{
    Address, AksharaError, Auditor, Block, BlockType, GraphId, GraphKey, GraphStore, InMemoryStore,
    IntegrityError, Manifest, ManifestId, SecretIdentity, traversal::create_valid_anchor,
};

async fn create_identity_anchor_manifest(
    store: &InMemoryStore,
    identity: &SecretIdentity,
) -> Manifest {
    let anchor_id = create_valid_anchor(store, identity).await;
    store.get_manifest(&anchor_id).await.unwrap().unwrap()
}

async fn create_data_manifest(
    store: &InMemoryStore,
    identity: &SecretIdentity,
    graph_key: &GraphKey,
    content: Vec<u8>,
    anchor: &Manifest,
) -> Manifest {
    let block = Block::new(
        anchor.graph_id(),
        content,
        BlockType::AksharaDataV1,
        vec![],
        graph_key,
        identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let manifest = Manifest::new(anchor.graph_id(), block.id(), vec![], anchor.id(), identity);
    store.put_manifest(&manifest).await.unwrap();
    manifest
}

#[tokio::test]
async fn test_auditor_accepts_valid_genesis_manifest() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let genesis = create_identity_anchor_manifest(&store, &identity).await;

    let auditor = Auditor::new(&store, master_pubkey);
    assert!(auditor.audit_manifest(&genesis).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_tampered_signature() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let genesis = create_identity_anchor_manifest(&store, &identity).await;

    let tampered_manifest = Manifest::from_raw_parts(
        genesis.id(),
        genesis.header.clone(),
        genesis.author().clone(),
        crate::Signature::new(vec![0u8; 64]),
    );

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    let result = auditor.audit_manifest(&tampered_manifest).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::ManifestIdMismatch(_)) | AksharaError::Crypto(_)
    ));
}

#[tokio::test]
async fn test_auditor_rejects_genesis_wrong_signer() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let wrong_identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let wrong_genesis = create_identity_anchor_manifest(&store, &wrong_identity).await;

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    let result = auditor.audit_manifest(&wrong_genesis).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::UnauthorizedSigner(_))
    ));
}

#[tokio::test]
async fn test_auditor_accepts_valid_data_manifest() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let master_pubkey = identity.public().signing_key().clone();
    let anchor = create_identity_anchor_manifest(&store, &identity).await;
    let graph_key = identity.derive_graph_key(&GraphId::new()).unwrap();

    let data_graph_id = GraphId::new();
    let block = Block::new(
        data_graph_id,
        b"test data".to_vec(),
        BlockType::AksharaDataV1,
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let data_manifest = Manifest::new(data_graph_id, block.id(), vec![], anchor.id(), &identity);
    store.put_manifest(&data_manifest).await.unwrap();

    let auditor = Auditor::new(&store, master_pubkey);
    assert!(auditor.audit_manifest(&data_manifest).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_invalid_anchor() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let anchor = create_identity_anchor_manifest(&store, &identity).await;
    let graph_key = identity.derive_graph_key(&GraphId::new()).unwrap();

    let data_manifest = create_data_manifest(
        &store,
        &identity,
        &graph_key,
        b"test data".to_vec(),
        &anchor,
    )
    .await;

    let fake_anchor = Manifest::new(
        GraphId::new(),
        data_manifest.content_root(),
        vec![],
        ManifestId::null(),
        &identity,
    );

    let bad_manifest = Manifest::new(
        GraphId::new(),
        data_manifest.content_root(),
        vec![],
        fake_anchor.id(),
        &identity,
    );

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    assert!(auditor.audit_manifest(&bad_manifest).await.is_err());
}

#[tokio::test]
async fn test_auditor_accepts_valid_block() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let graph_key = GraphKey::generate(&mut rand::rngs::OsRng);

    let block = Block::new(
        GraphId::new(),
        b"test content".to_vec(),
        BlockType::AksharaDataV1,
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    assert!(auditor.audit_block(&block).is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_tampered_block() {
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let graph_key = GraphKey::generate(&mut rand::rngs::OsRng);

    let block = Block::new(
        GraphId::new(),
        b"test content".to_vec(),
        BlockType::AksharaDataV1,
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();

    let tampered_block = Block::from_raw_parts(
        crate::BlockId::from_sha256(&[0xFF; 32]),
        block.author().clone(),
        block.signature().clone(),
        block.content().clone(),
        block.block_type().clone(),
        block.parents().to_vec(),
    );

    let store = InMemoryStore::new();
    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    let result = auditor.audit_block(&tampered_block);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::BlockIdMismatch(_))
    ));
}

#[tokio::test]
async fn test_auditor_verify_existence_manifest() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let genesis = create_identity_anchor_manifest(&store, &identity).await;

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    assert!(
        auditor
            .verify_existence(&Address::from(genesis.id()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_auditor_verify_existence_block() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let graph_key = GraphKey::generate(&mut rand::rngs::OsRng);

    let block = Block::new(
        GraphId::new(),
        b"test content".to_vec(),
        BlockType::AksharaDataV1,
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    assert!(
        auditor
            .verify_existence(&Address::from(block.id()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_auditor_verify_existence_missing_manifest() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let fake_id = ManifestId::from_sha256(&[0xAA; 32]);

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    let result = auditor.verify_existence(&Address::from(fake_id)).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AksharaError::Store(_)));
}

#[tokio::test]
async fn test_auditor_verify_existence_missing_block() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let fake_id = crate::BlockId::from_sha256(&[0xBB; 32]);

    let auditor = Auditor::new(&store, identity.public().signing_key().clone());
    let result = auditor.verify_existence(&Address::from(fake_id)).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AksharaError::Store(_)));
}

#[tokio::test]
async fn test_auditor_with_latest_identity() {
    let store = InMemoryStore::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let genesis = create_identity_anchor_manifest(&store, &identity).await;

    let auditor = Auditor::new(&store, identity.public().signing_key().clone())
        .with_latest_identity(genesis.id());

    assert!(auditor.audit_manifest(&genesis).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_admin_non_legislator() {
    let store = InMemoryStore::new();
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
    let executive_identity =
        SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "m/44'/999'/0'/1'/0'").unwrap();

    let graph_id = GraphId::new();
    let identity_key = GraphKey::new([0u8; 32]);

    let auth_block = Block::new(
        graph_id,
        vec![],
        BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        &executive_identity,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    let mut index_map = std::collections::BTreeMap::new();
    index_map.insert(
        format!(
            "credentials/{}",
            executive_identity.public().signing_key().to_hex()
        ),
        *Address::from(auth_block.id()).as_cid(),
    );
    let index_block = Block::new_index(
        graph_id,
        index_map,
        vec![],
        &identity_key,
        &executive_identity,
    )
    .unwrap();
    store.put_block(&index_block).await.unwrap();

    let genesis = Manifest::new(
        graph_id,
        index_block.id(),
        vec![],
        ManifestId::null(),
        &executive_identity,
    );
    store.put_manifest(&genesis).await.unwrap();

    let auditor = Auditor::new(&store, executive_identity.public().signing_key().clone());
    assert!(auditor.audit_manifest(&genesis).await.is_err());
}
