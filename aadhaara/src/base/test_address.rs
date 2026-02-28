use crate::base::address::{
    Address, BlockId, CODEC_SOVEREIGN_BLOCK, CODEC_SOVEREIGN_MANIFEST, ManifestId,
};
use std::str::FromStr;

#[test]
fn test_cid_creation_from_sha256() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);

    assert_eq!(cid.codec(), CODEC_SOVEREIGN_BLOCK);
    assert_eq!(cid.to_bytes().len(), 36); // 1 (version) + 1 (codec) + 1 (hash) + 1 (len) + 32 (digest)
}

#[test]
fn test_cid_codec_enforcement() {
    let digest = [0u8; 32];
    let block_id = BlockId::from_sha256(&digest);
    let manifest_id = ManifestId::from_sha256(&digest);

    assert_eq!(block_id.codec(), CODEC_SOVEREIGN_BLOCK);
    assert_eq!(manifest_id.codec(), CODEC_SOVEREIGN_MANIFEST);
}

#[test]
fn test_cid_type_confusion_protection() {
    let digest = [0u8; 32];
    let block_id = BlockId::from_sha256(&digest);
    let addr = Address::from(block_id);

    // Should succeed
    assert!(BlockId::try_from(addr).is_ok());

    // Should fail (codec mismatch)
    assert!(ManifestId::try_from(addr).is_err());
}

#[test]
fn test_cid_string_roundtrip() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);
    let s = cid.to_string();

    let restored = BlockId::from_str(&s).unwrap();
    assert_eq!(cid, restored);
}

#[test]
fn test_cid_strict_from_bytes() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);
    let bytes = cid.to_bytes();

    // 1. Success case
    assert!(BlockId::try_from(&bytes[..]).is_ok());

    // 2. Trailing junk should fail (The Fortress Rule)
    let mut bad_bytes = bytes.clone();
    bad_bytes.push(0xFF);
    assert!(BlockId::try_from(&bad_bytes[..]).is_err());
}

#[test]
fn test_cid_fails_on_malformed_string() {
    assert!(BlockId::from_str("not-a-cid").is_err());
    assert!(
        BlockId::from_str("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").is_err()
    ); // Valid CID, wrong codec
}

#[test]
fn test_cid_serde_json_representation() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);
    let json = serde_json::to_string(&cid).unwrap();

    // Should be represented as a string in JSON
    assert!(json.starts_with("\"baf"));

    let restored: BlockId = serde_json::from_str(&json).unwrap();
    assert_eq!(cid, restored);
}

pub mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn p_cid_roundtrip_integrity(digest in prop::collection::vec(0u8..255, 32)) {
            let cid = BlockId::from_sha256(&digest);
            let bytes = cid.to_bytes();
            let restored = BlockId::try_from(&bytes[..]).unwrap();
            prop_assert_eq!(cid, restored);
        }

        #[test]
        fn p_cid_parsing_robustness(data in prop::collection::vec(0u8..255, 0..100)) {
            // Parser must never panic, regardless of input
            let _ = BlockId::try_from(&data[..]);
        }
    }
}
