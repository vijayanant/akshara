use thiserror::Error;

#[derive(Error, Debug)]
pub enum SovereignError {
    #[error("Pact is in invalid state for this operation: expected {expected}, found {found}")]
    InvalidState { expected: String, found: String },
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Pact cannot be sealed because it is empty")]
    EmptyPact,
    #[error("Invalid key length: expected {expected}, found {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
}
