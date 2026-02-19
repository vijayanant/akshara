use crate::base::address::{Address, BlockId, ManifestId};
use thiserror::Error;

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

    #[error("Protocol reconciliation failed: {0}")]
    Protocol(#[from] ProtocolError),

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

    #[error("Type mismatch: Address {0} is not a valid {1}")]
    TypeMismatch(Address, &'static str),

    #[error("Block ID {0:?} does not match its content hash")]
    BlockIdMismatch(BlockId),

    #[error("Manifest {0:?} ID does not match its metadata hash")]
    ManifestIdMismatch(ManifestId),

    #[error("Traversal depth limit exceeded (max: {0})")]
    DepthLimitExceeded(usize),

    #[error("Cycle detected at address: {0}")]
    CycleDetected(Address),

    #[error("Unauthorized signer: {0}")]
    UnauthorizedSigner(String),
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

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Heads count exceeds limit (max: {0})")]
    TooManyHeads(usize),

    #[error("Delta size exceeds limit (max: {0})")]
    DeltaTooLarge(usize),

    #[error("Inconsistent graph: {0}")]
    InconsistentGraph(String),
}
