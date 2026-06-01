use akshara_aadhaara::{BlockId, Signature, SigningPublicKey};
use serde::{Deserialize, Serialize};

/// A wrapper for structured fields that retains their cryptographic metadata and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocField<T> {
    /// The deserialized value of the field.
    pub value: T,
    /// The Block ID (CID) of the block storing this value.
    pub block_id: BlockId,
    /// The public key of the author who committed this value.
    pub author: SigningPublicKey,
    /// The signature of the author attesting to this value.
    pub signature: Signature,
}

impl<T> DocField<T> {
    /// Create a new metadata-preserving document field wrapper.
    pub fn new(
        value: T,
        block_id: BlockId,
        author: SigningPublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            value,
            block_id,
            author,
            signature,
        }
    }
}
