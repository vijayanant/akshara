use crate::base::encoding::{from_canonical_bytes, to_canonical_bytes};
use std::collections::BTreeMap;

#[test]
fn test_canonical_roundtrip() {
    let mut map = BTreeMap::new();
    map.insert("z".to_string(), 100u64);
    map.insert("a".to_string(), 1u64);

    let bytes = to_canonical_bytes(&map).expect("Serialization failed");

    assert_eq!(bytes[1], 0x61);

    let restored: BTreeMap<String, u64> =
        from_canonical_bytes(&bytes).expect("Deserialization failed");
    assert_eq!(map, restored);
}

#[test]
fn test_negative_malleability_rejection() {
    let val = 5u64;
    let canonical_bytes = to_canonical_bytes(&val).unwrap();

    assert_eq!(canonical_bytes, vec![0x05]);

    let non_canonical = vec![0x19, 0x00, 0x05];
    let res: Result<u64, _> = from_canonical_bytes(&non_canonical);

    assert!(
        res.is_err(),
        "Decoder must reject non-minimal integer encoding"
    );
}

#[test]
fn test_from_canonical_bytes_rejects_invalid_cbor() {
    let invalid_cbor = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let res: Result<String, _> = from_canonical_bytes(&invalid_cbor);

    assert!(res.is_err(), "Decoder must reject completely invalid CBOR");
}

#[test]
fn test_from_canonical_bytes_rejects_empty_input() {
    let empty: Vec<u8> = vec![];
    let res: Result<String, _> = from_canonical_bytes(&empty);

    assert!(res.is_err(), "Decoder must reject empty input");
}

#[test]
fn test_to_canonical_bytes_handles_nested_structures() {
    let mut outer = BTreeMap::new();
    let mut inner = BTreeMap::new();
    inner.insert("key".to_string(), 42u64);
    outer.insert("nested".to_string(), inner);

    let bytes = to_canonical_bytes(&outer).unwrap();
    let restored: BTreeMap<String, BTreeMap<String, u64>> = from_canonical_bytes(&bytes).unwrap();

    assert_eq!(outer, restored);
}

#[test]
fn test_from_canonical_bytes_rejects_trailing_data() {
    let val = 42u64;
    let canonical = to_canonical_bytes(&val).unwrap();

    let mut with_trailing = canonical.clone();
    with_trailing.extend_from_slice(&[0x00, 0x00]);

    let res: Result<u64, _> = from_canonical_bytes(&with_trailing);

    assert!(res.is_err(), "Decoder must reject input with trailing data");
}
