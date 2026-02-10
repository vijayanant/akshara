use sovereign_core::graph::BlockId;
use sovereign_core::error::{SovereignError, IntegrityError};
use std::str::FromStr;

#[test]
fn test_cid_creation_from_sha256() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);

    assert_eq!(cid.version(), 1);
    assert_eq!(cid.codec(), 0x50);
    assert_eq!(cid.hash_type(), 0x12);
}

#[test]
fn test_cid_string_roundtrip() {
    let digest = [0xABu8; 32];
    let cid = BlockId::from_sha256(&digest);

    let cid_str = cid.to_string();
    assert!(cid_str.starts_with('b'));

    let restored = BlockId::from_str(&cid_str).expect("Failed to parse CID string");
    assert_eq!(cid, restored);
}

#[test]
fn test_cid_fails_on_malformed_string() {
    let bad_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3jha637iehcq89y";
    let mut corrupted = bad_cid.to_string();
    corrupted.pop();
    assert!(BlockId::from_str(&corrupted).is_err());
}

#[test]
fn test_cid_strict_from_bytes() {
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    let hash = Code::Sha2_256.digest(b"hello");
    let cid = Cid::new_v1(0x50, hash);
    let mut bytes = cid.to_bytes();

    // Valid parse
    assert!(BlockId::try_from(bytes.as_slice()).is_ok());

    // Add junk data
    bytes.extend_from_slice(b"junk");

    // Must fail due to trailing bytes
    assert!(BlockId::try_from(bytes.as_slice()).is_err());
}

#[test]
fn test_cid_type_confusion_protection() {
    use sovereign_core::graph::ManifestId;

    let digest = [0u8; 32];
    let block_id = BlockId::from_sha256(&digest);
    let bytes = block_id.0.to_bytes();

    // Attempt to parse BlockId bytes as a ManifestId
    // This MUST fail because the multicodec (0x50 vs 0x51) is different.
    let result = ManifestId::try_from(bytes.as_slice());

    assert!(
        result.is_err(),
        "ManifestId should reject CID with Block codec"
    );
}

#[test]
fn test_cid_serde_json_representation() {
    let digest = [0xCCu8; 32];
    let cid = BlockId::from_sha256(&digest);

    let json = serde_json::to_string(&cid).expect("Failed to serialize");

    // Ensure it's a JSON string
    assert!(json.starts_with('\"'));

    let restored: BlockId = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(cid, restored);
}

#[test]
fn test_cid_codec_enforcement() {
    use multihash_codetable::{Code, MultihashDigest};
    use cid::Cid;

    // 1. Create a valid CID but with the WRONG codec (e.g. Git = 0x71)
    let hash = Code::Sha2_256.digest(b"not_a_sovereign_block");
    let git_cid = Cid::new_v1(0x71, hash);
    let git_cid_str = git_cid.to_string();

    // 2. Attempt to parse this into a BlockId
    // This MUST fail because BlockId only accepts 0x50
    let result = BlockId::from_str(&git_cid_str);
    
    assert!(result.is_err(), "BlockId must reject CIDs with non-Sovereign codecs");
    
    if let Err(SovereignError::Integrity(IntegrityError::MalformedId)) = result {
        // Success: Correct error returned
    } else {
        panic!("Expected MalformedId error, got {:?}", result);
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: Parsing random bytes must never panic and must only
        /// succeed if the bytes represent a valid Sovereign CID.
        #[test]
        fn p_cid_parsing_robustness(ref bytes in any::<Vec<u8>>()) {
            let _ = BlockId::try_from(bytes.as_slice());
        }

        /// Property: A CID created from a valid digest must always round-trip
        /// through string and byte representations.
        #[test]
        fn p_cid_roundtrip_integrity(ref digest in any::<[u8; 32]>()) {
            let original = BlockId::from_sha256(digest);

            // Byte roundtrip
            let bytes = original.0.to_bytes();
            let restored_bytes = BlockId::try_from(bytes.as_slice()).expect("Byte roundtrip failed");
            prop_assert_eq!(&original, &restored_bytes);

            // String roundtrip
            let s = original.to_string();
            let restored_str = BlockId::from_str(&s).expect("String roundtrip failed");
            prop_assert_eq!(&original, &restored_str);
        }
    }
}
