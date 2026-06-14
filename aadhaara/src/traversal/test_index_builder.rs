use crate::{Address, BlockId, IndexBuilder};

#[test]
fn test_index_builder_rejects_empty_path() {
    let mut builder = IndexBuilder::new();
    let fake_addr = Address::from(BlockId::from_sha256(&[0xFF; 32]));

    let result = builder.insert("", fake_addr);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Path cannot be empty")
    );
}

#[test]
fn test_index_builder_rejects_only_slashes() {
    let mut builder = IndexBuilder::new();
    let fake_addr = Address::from(BlockId::from_sha256(&[0x01; 32]));

    let result = builder.insert("///", fake_addr);
    assert!(result.is_err());
}

#[test]
fn test_index_builder_path_conflict_leaf_to_branch() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x11; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x22; 32]));

    builder.insert("cases", addr1).unwrap();

    let result = builder.insert("cases/summary", addr2);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Path conflict"));
}

#[test]
fn test_index_builder_path_conflict_branch_to_leaf() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x33; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x44; 32]));

    builder.insert("cases/summary", addr1).unwrap();

    let result = builder.insert("cases", addr2);

    assert!(result.is_ok());
}

#[test]
fn test_index_builder_allows_sibling_paths() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x55; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x66; 32]));

    builder.insert("cases/summary1", addr1).unwrap();
    let result = builder.insert("cases/summary2", addr2);
    assert!(result.is_ok());
}

#[test]
fn test_index_builder_handles_leading_trailing_slashes() {
    let mut builder = IndexBuilder::new();
    let addr = Address::from(BlockId::from_sha256(&[0x77; 32]));

    let result = builder.insert("/cases/summary/", addr);
    assert!(result.is_ok());
}

#[test]
fn test_index_builder_handles_multiple_consecutive_slashes() {
    let mut builder = IndexBuilder::new();
    let addr = Address::from(BlockId::from_sha256(&[0x88; 32]));

    let result = builder.insert("cases//alpha///summary", addr);
    assert!(result.is_ok());
}

#[test]
fn test_index_builder_default() {
    let mut builder = IndexBuilder::default();
    assert!(
        builder
            .insert("test", Address::from(BlockId::from_sha256(&[0x99; 32])))
            .is_ok()
    );
}

#[test]
fn test_index_builder_remove() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x11; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x22; 32]));

    builder.insert("foo/bar", addr1).unwrap();
    builder.insert("foo/baz", addr2).unwrap();

    // Verify remove returns Ok for non-existent path
    assert!(builder.remove("foo/not_exist").is_ok());
    assert!(builder.remove("xyz").is_ok());

    // Verify we can remove foo/bar
    assert!(builder.remove("foo/bar").is_ok());

    // Re-inserting should work since there is no conflict now
    assert!(builder.insert("foo/bar", addr1).is_ok());

    // Remove it again
    assert!(builder.remove("foo/bar").is_ok());
}

#[tokio::test]
async fn test_index_builder_import_and_roundtrip() {
    use crate::test_utils::TestFactory;

    let factory = TestFactory::new().await;
    let b1 = factory.create_block(b"data1").await;
    let b2 = factory.create_block(b"data2").await;
    let addr1 = Address::from(b1.id());
    let addr2 = Address::from(b2.id());

    // 1. Build and materialize a virtual tree
    let mut builder = IndexBuilder::new();
    builder.insert("docs/report", addr1).unwrap();
    builder.insert("docs/nested/summary", addr2).unwrap();

    let root_id = builder
        .build(
            factory.graph_id,
            factory.store.as_ref(),
            &factory.identity,
            &factory.graph_key,
        )
        .await
        .unwrap();

    // 2. Import into a fresh builder
    let mut imported_builder = IndexBuilder::new();
    imported_builder
        .import_from_root(
            &factory.graph_id,
            &root_id,
            factory.store.as_ref(),
            &factory.graph_key,
        )
        .await
        .unwrap();

    // 3. Re-build from imported tree and verify root ID is identical
    let new_root_id = imported_builder
        .build(
            factory.graph_id,
            factory.store.as_ref(),
            &factory.identity,
            &factory.graph_key,
        )
        .await
        .unwrap();

    assert_eq!(root_id, new_root_id);
}
