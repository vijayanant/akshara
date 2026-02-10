use sovereign_core::graph::BlockId;
use std::str::FromStr;

#[test]
fn test_cid_creation_from_sha256() {
    let digest = [0u8; 32];
    // BlockId should now be a CID-compatible structure
    let cid = BlockId::from_sha256(&digest);

    assert_eq!(cid.version(), 1);
    assert_eq!(cid.codec(), 0x50); // Sovereign Block multicodec
    assert_eq!(cid.hash_type(), 0x12); // SHA2-256
}

#[test]
fn test_cid_string_roundtrip() {
    let digest = [0xABu8; 32];
    let cid = BlockId::from_sha256(&digest);

    let cid_str = cid.to_string();
    // Should start with 'b' (Base32 prefix)
    assert!(cid_str.starts_with('b'));

    let restored = BlockId::from_str(&cid_str).expect("Failed to parse CID string");
    assert_eq!(cid, restored);
}
