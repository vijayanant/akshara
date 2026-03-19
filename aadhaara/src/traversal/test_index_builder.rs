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

    builder.insert("folder", addr1).unwrap();

    let result = builder.insert("folder/file.txt", addr2);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Path conflict"));
}

#[test]
fn test_index_builder_path_conflict_branch_to_leaf() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x33; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x44; 32]));

    builder.insert("folder/file.txt", addr1).unwrap();

    let result = builder.insert("folder", addr2);

    assert!(result.is_ok());
}

#[test]
fn test_index_builder_allows_sibling_paths() {
    let mut builder = IndexBuilder::new();
    let addr1 = Address::from(BlockId::from_sha256(&[0x55; 32]));
    let addr2 = Address::from(BlockId::from_sha256(&[0x66; 32]));

    builder.insert("folder/file1.txt", addr1).unwrap();
    let result = builder.insert("folder/file2.txt", addr2);
    assert!(result.is_ok());
}

#[test]
fn test_index_builder_handles_leading_trailing_slashes() {
    let mut builder = IndexBuilder::new();
    let addr = Address::from(BlockId::from_sha256(&[0x77; 32]));

    let result = builder.insert("/folder/file.txt/", addr);
    assert!(result.is_ok());
}

#[test]
fn test_index_builder_handles_multiple_consecutive_slashes() {
    let mut builder = IndexBuilder::new();
    let addr = Address::from(BlockId::from_sha256(&[0x88; 32]));

    let result = builder.insert("folder//subfolder///file.txt", addr);
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
