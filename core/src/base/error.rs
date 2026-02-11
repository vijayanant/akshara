use thiserror::Error;

use crate::base::{BlockId, ManifestId};

#[derive(Error, Debug)]
pub enum SovereignError {
    #[error("Cryptographic failure: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Data integrity failure: {0}")]
    Integrity(#[from] IntegrityError),

    #[error("Identity management error: {0}")]
    Identity(#[from] IdentityError),

    #[error("Storage operation failed: {0}")]
    Store(#[from] StoreError),

    #[error("Internal system error: {0}")]
    InternalError(String),
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption operation failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption operation failed (wrong key or tampered data): {0}")]
    DecryptionFailed(String),

    #[error("Digital signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("Invalid key format or length: {0}")]
    InvalidKeyFormat(String),
}

#[derive(Error, Debug)]
pub enum IntegrityError {
    #[error("Identifier is malformed or has invalid length")]
    MalformedId,

    #[error("Block ID {0:?} does not match its content hash")]
    BlockIdMismatch(BlockId),

    #[error("Manifest {0:?} Merkle Root does not match active blocks")]
    ManifestMerkleMismatch(ManifestId),

    #[error("Manifest {0:?} ID does not match its metadata hash")]
    ManifestIdMismatch(ManifestId),
}

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Mnemonic phrase is invalid: {0}")]
    MnemonicInvalid(String),

    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Storage lock is poisoned (concurrency panic)")]
    LockPoisoned,

    #[error("Object not found: {0}")]
    NotFound(String),

    #[error("IO Error: {0}")]
    IoError(String),
}
