use sovereign_core::error::SovereignError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] SovereignError),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Internal SDK error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timed out")]
    Timeout,

    #[error("Server returned error: {0}")]
    ServerError(String),
}
