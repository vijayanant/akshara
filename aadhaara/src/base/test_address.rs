use crate::base::address::{
    Address, BlockId, CODEC_AKSHARA_BLOCK, CODEC_AKSHARA_MANIFEST, ManifestId,
};
use multihash_codetable::MultihashDigest;
use std::str::FromStr;

#[test]
fn test_cid_creation_from_sha256() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);

    assert_eq!(cid.codec(), CODEC_AKSHARA_BLOCK);
    assert_eq!(cid.to_bytes().len(), 36); // 1 (version) + 1 (codec) + 1 (hash) + 1 (len) + 32 (digest)
}

#[test]
fn test_cid_codec_enforcement() {
    let digest = [0u8; 32];
    let block_id = BlockId::from_sha256(&digest);
    let manifest_id = ManifestId::from_sha256(&digest);

    assert_eq!(block_id.codec(), CODEC_AKSHARA_BLOCK);
    assert_eq!(manifest_id.codec(), CODEC_AKSHARA_MANIFEST);
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
fn test_cid_binary_cbor_representation() {
    let digest = [0u8; 32];
    let cid = BlockId::from_sha256(&digest);

    let bytes = crate::base::encoding::to_canonical_bytes(&cid).unwrap();

    // Binary CBOR for Tag 42 (IPLD Link) starts with 0xD8 0x2A.
    assert_eq!(bytes[0], 0xD8);
    assert_eq!(bytes[1], 42);

    let restored: BlockId = crate::base::encoding::from_canonical_bytes(&bytes[..]).unwrap();
    assert_eq!(cid, restored);
}

#[test]
fn test_negative_reject_generic_codecs() {
    let digest = [0u8; 32];
    let hash = multihash_codetable::Code::Sha2_256.digest(&digest);

    // 1. Rejects 0x55 (Raw)
    let raw_cid = cid::Cid::new_v1(0x55, hash);
    assert!(BlockId::try_from(Address::from(raw_cid)).is_err());

    // 2. Rejects 0x71 (DAG-CBOR)
    let cbor_cid = cid::Cid::new_v1(0x71, hash);
    assert!(ManifestId::try_from(Address::from(cbor_cid)).is_err());
}

#[test]
fn test_negative_reject_cid_v0() {
    // CIDv0 is always 34 bytes (0x12 0x20 [32-byte digest])
    let mut v0_bytes = vec![0x12, 0x20];
    v0_bytes.extend_from_slice(&[0u8; 32]);

    // Our gate must reject V0
    assert!(Address::try_from(&v0_bytes[..]).is_err());
}

#[test]
fn test_negative_reject_malformed_multihash() {
    let digest = [0u8; 32];
    // Use Sha2_512 as an "unexpected" algorithm
    let hash = multihash_codetable::Code::Sha2_512.digest(&digest);

    let unexpected_cid = cid::Cid::new_v1(CODEC_AKSHARA_BLOCK, hash);
    let addr = Address::from(unexpected_cid);

    // While this is a valid CID, our factory methods force SHA2-256.
    // If we receive a different hash algorithm via the network, we can still parse it as an Address,
    // but specific logic may choose to reject it later.
    assert!(BlockId::try_from(addr).is_ok()); // The gate only checks the codec
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
