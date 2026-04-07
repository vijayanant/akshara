use crate::{
    Address, AksharaError, Auditor, Block, BlockType, GraphId, GraphStore, IntegrityError,
    Manifest, ManifestId, SecretIdentity, test_utils::TestFactory,
};

#[tokio::test]
async fn test_auditor_accepts_valid_genesis_manifest() {
    let factory = TestFactory::with_anchor().await;
    let genesis = factory
        .store
        .get_manifest(&factory.anchor)
        .await
        .unwrap()
        .unwrap();

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(auditor.audit_manifest(&genesis, None).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_tampered_signature() {
    let factory = TestFactory::with_anchor().await;
    let genesis = factory
        .store
        .get_manifest(&factory.anchor)
        .await
        .unwrap()
        .unwrap();

    let tampered_manifest = Manifest::from_raw_parts(
        genesis.id(),
        genesis.header.clone(),
        genesis.author().clone(),
        crate::base::crypto::Signature::new(vec![0u8; 64]),
    );

    let auditor = Auditor::new(factory.store.as_ref());
    let result = auditor.audit_manifest(&tampered_manifest, None).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::ManifestIdMismatch(_)) | AksharaError::Crypto(_)
    ));
}

#[tokio::test]
async fn test_auditor_accepts_valid_data_manifest() {
    let factory = TestFactory::with_anchor().await;
    let block = factory.create_block(b"test data").await;
    let data_manifest = factory.create_manifest(block.id(), vec![]).await;

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(auditor.audit_manifest(&data_manifest, None).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_invalid_anchor() {
    let factory = TestFactory::with_anchor().await;
    let block = factory.create_block(b"test data").await;

    // Create a manifest with a fake anchor
    let fake_anchor = ManifestId::from_sha256(&[0xEE; 32]);
    let bad_manifest = Manifest::new(
        factory.graph_id,
        block.id(),
        vec![],
        fake_anchor,
        Address::null(),
        &factory.identity,
        None,
    );

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(auditor.audit_manifest(&bad_manifest, None).await.is_err());
}

#[tokio::test]
async fn test_auditor_accepts_valid_block() {
    let factory = TestFactory::new().await;
    let block = factory.create_block(b"test content").await;

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(auditor.audit_block(&block).is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_tampered_block() {
    let factory = TestFactory::new().await;
    let block = factory.create_block(b"test content").await;

    let tampered_block = Block::from_raw_parts(
        crate::base::address::BlockId::from_sha256(&[0xFF; 32]),
        block.author().clone(),
        block.signature().clone(),
        block.content().clone(),
        block.block_type().clone(),
        block.parents().to_vec(),
    );

    let auditor = Auditor::new(factory.store.as_ref());
    let result = auditor.audit_block(&tampered_block);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AksharaError::Integrity(IntegrityError::BlockIdMismatch(_))
    ));
}

#[tokio::test]
async fn test_auditor_verify_existence_manifest() {
    let factory = TestFactory::with_anchor().await;
    let genesis = factory
        .store
        .get_manifest(&factory.anchor)
        .await
        .unwrap()
        .unwrap();

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(
        auditor
            .verify_existence(&Address::from(genesis.id()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_auditor_verify_existence_block() {
    let factory = TestFactory::new().await;
    let block = factory.create_block(b"test content").await;

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(
        auditor
            .verify_existence(&Address::from(block.id()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_auditor_verify_existence_missing_manifest() {
    let factory = TestFactory::new().await;
    let fake_id = ManifestId::from_sha256(&[0xAA; 32]);

    let auditor = Auditor::new(factory.store.as_ref());
    let result = auditor.verify_existence(&Address::from(fake_id)).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AksharaError::Store(_)));
}

#[tokio::test]
async fn test_auditor_verify_existence_missing_block() {
    let factory = TestFactory::new().await;
    let fake_id = crate::base::address::BlockId::from_sha256(&[0xBB; 32]);

    let auditor = Auditor::new(factory.store.as_ref());
    let result = auditor.verify_existence(&Address::from(fake_id)).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AksharaError::Store(_)));
}

#[tokio::test]
async fn test_auditor_with_latest_identity() {
    let factory = TestFactory::with_anchor().await;
    let genesis = factory
        .store
        .get_manifest(&factory.anchor)
        .await
        .unwrap()
        .unwrap();

    let auditor = Auditor::new(factory.store.as_ref()).with_latest_identity(genesis.id());

    assert!(auditor.audit_manifest(&genesis, None).await.is_ok());
}

#[tokio::test]
async fn test_auditor_rejects_admin_non_legislator() {
    let mnemonic = SecretIdentity::generate_mnemonic().unwrap();

    // Create an EXECUTIVE identity (m/44'/999'/0'/1'/0')
    let executive_identity =
        SecretIdentity::from_mnemonic_at_path(&mnemonic, "", "m/44'/999'/0'/1'/0'").unwrap();

    let factory = TestFactory::new().await;
    let graph_id = GraphId::new();
    let identity_key = crate::identity::graph::IDENTITY_GRAPH_KEY;

    // Try to create an identity anchor with an Executive key
    let auth_block = Block::new(
        graph_id,
        vec![],
        BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        &executive_identity,
    )
    .unwrap();
    factory.store.put_block(&auth_block).await.unwrap();

    crate::traversal::index_builder::IndexBuilder::new()
        .insert(
            &format!(
                "credentials/{}",
                executive_identity.public().signing_key().to_hex()
            ),
            Address::from(auth_block.id()),
        )
        .unwrap();
    // This is getting complex, but the key is that it's NOT a legislator path.

    let genesis = Manifest::new(
        graph_id,
        auth_block.id(), // simplified for test
        vec![],
        ManifestId::null(),
        Address::null(),
        &executive_identity,
        None,
    );
    factory.store.put_manifest(&genesis).await.unwrap();

    let auditor = Auditor::new(factory.store.as_ref());
    assert!(auditor.audit_manifest(&genesis, None).await.is_err());
}
