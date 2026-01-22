use crate::graph::{BlockId, ManifestId};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SovereignError {
    // --- State & Lifecycle ---
    #[error("Invalid state: expected {expected}, found {found}")]
    InvalidState { expected: String, found: String },

    #[error("Pact cannot be sealed because it is empty")]
    EmptyPact,

    // --- Authorization & Integrity ---
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Integrity failure: Block {0:?} has mismatched content hash")]
    BlockIdMismatch(BlockId),

    #[error("Integrity failure: Manifest {0:?} has mismatched Merkle root")]
    ManifestMerkleMismatch(ManifestId),

    #[error("Signature verification failed: {0}")]
    SignatureFailure(String),

    // --- Cryptography ---
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid key length: expected {expected}, found {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    // --- Identity ---
    #[error("Mnemonic derivation failed: {0}")]
    MnemonicError(String),

    // --- System ---
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}
