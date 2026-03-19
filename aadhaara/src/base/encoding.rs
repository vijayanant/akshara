use crate::base::error::AksharaError;
use serde::{Serialize, de::DeserializeOwned};

/// Performs strict canonical DAG-CBOR serialization.
///
/// This is the "Universal Physics" of the Akshara system. It ensures that
/// any given data structure has exactly ONE bit-identical representation.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AksharaError> {
    serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| AksharaError::InternalError(format!("DAG-CBOR serialization failed: {}", e)))
}

/// Performs strict canonical DAG-CBOR deserialization.
///
/// This function enforces the IPLD DAG-CBOR subset by re-encoding the deserialized
/// object and comparing the resulting bits with the original input. This ensures
/// absolute bit-identicality and eliminates all forms of encoding malleability.
pub fn from_canonical_bytes<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AksharaError> {
    let val: T = serde_ipld_dagcbor::from_slice(bytes).map_err(|e| {
        AksharaError::InternalError(format!("DAG-CBOR deserialization failed: {}", e))
    })?;

    // THE CANONICAL RITUAL: Re-encode and compare bits
    let canonical_bytes = to_canonical_bytes(&val)?;
    if bytes != canonical_bytes {
        return Err(AksharaError::Integrity(
            crate::base::error::IntegrityError::MalformedId,
        ));
    }

    Ok(val)
}
