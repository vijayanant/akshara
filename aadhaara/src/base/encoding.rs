use crate::base::error::SovereignError;
use serde::{Serialize, de::DeserializeOwned};

/// Performs strict canonical DAG-CBOR serialization.
///
/// This is the "Universal Physics" of the Akshara system. It ensures that
/// any given data structure has exactly ONE bit-identical representation.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SovereignError> {
    serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| SovereignError::InternalError(format!("DAG-CBOR serialization failed: {}", e)))
}

/// Performs strict canonical DAG-CBOR deserialization.
///
/// This function enforces the IPLD DAG-CBOR subset by re-encoding the deserialized
/// object and comparing the resulting bits with the original input. This ensures
/// absolute bit-identicality and eliminates all forms of encoding malleability.
pub fn from_canonical_bytes<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, SovereignError> {
    let val: T = serde_ipld_dagcbor::from_slice(bytes).map_err(|e| {
        SovereignError::InternalError(format!("DAG-CBOR deserialization failed: {}", e))
    })?;

    // THE CANONICAL RITUAL: Re-encode and compare bits
    let canonical_bytes = to_canonical_bytes(&val)?;
    if bytes != canonical_bytes {
        return Err(SovereignError::Integrity(
            crate::base::error::IntegrityError::MalformedId,
        ));
    }

    Ok(val)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_canonical_roundtrip() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), 100u64);
        map.insert("a".to_string(), 1u64);

        let bytes = to_canonical_bytes(&map).expect("Serialization failed");

        // In DAG-CBOR, keys must be sorted lexicographically.
        // "a" (0x61) comes before "z" (0x7a).
        assert_eq!(bytes[1], 0x61);

        let restored: BTreeMap<String, u64> =
            from_canonical_bytes(&bytes).expect("Deserialization failed");
        assert_eq!(map, restored);
    }

    #[test]
    fn test_negative_malleability_rejection() {
        let val = 5u64;
        let canonical_bytes = to_canonical_bytes(&val).unwrap();

        // Canonical encoding for 5 is just [0x05].
        assert_eq!(canonical_bytes, vec![0x05]);

        // Non-canonical encoding: 5 as a 2-byte integer [0x19, 0x00, 0x05]
        let non_canonical = vec![0x19, 0x00, 0x05];

        let res: Result<u64, _> = from_canonical_bytes(&non_canonical);

        // The strict DAG-CBOR decoder MUST reject this.
        assert!(
            res.is_err(),
            "Decoder must reject non-minimal integer encoding"
        );
    }
}
