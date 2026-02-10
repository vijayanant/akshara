use sovereign_core::error::{
    CryptoError, IdentityError, IntegrityError, SovereignError, StoreError,
};
use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Protocol error: {0}")]
    Core(#[from] SovereignError),

    #[error("Invalid request: {0}")]
    InvalidInput(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl From<RelayError> for Status {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Core(core_err) => map_sovereign_error(core_err),
            RelayError::InvalidInput(msg) => Status::invalid_argument(msg),
            RelayError::Internal(msg) => Status::internal(msg),
        }
    }
}

/// Private helper to map Core errors to Status.
/// This logic is encapsulated within the RelayError conversion.
fn map_sovereign_error(err: SovereignError) -> Status {
    match err {
        SovereignError::Integrity(IntegrityError::BlockIdMismatch(_))
        | SovereignError::Integrity(IntegrityError::ManifestMerkleMismatch(_))
        | SovereignError::Integrity(IntegrityError::ManifestIdMismatch(_))
        | SovereignError::Integrity(IntegrityError::MalformedId) => {
            Status::invalid_argument(format!("Integrity Check Failed: {}", err))
        }

        SovereignError::Crypto(CryptoError::InvalidSignature(_)) => {
            Status::unauthenticated(format!("Crypto Failure: {}", err))
        }
        SovereignError::Crypto(CryptoError::InvalidKeyFormat(_)) => {
            Status::invalid_argument(format!("Crypto Failure: {}", err))
        }
        SovereignError::Crypto(_) => Status::internal(err.to_string()),

        SovereignError::Identity(IdentityError::MnemonicInvalid(_)) => {
            Status::invalid_argument(format!("Identity Error: {}", err))
        }
        SovereignError::Identity(_) => Status::unauthenticated(err.to_string()),

        SovereignError::Store(StoreError::NotFound(msg)) => Status::not_found(msg),
        SovereignError::Store(StoreError::LockPoisoned) => {
            Status::internal("Internal Storage Error (Lock)")
        }
        SovereignError::Store(StoreError::IoError(msg)) => {
            Status::internal(format!("Storage IO Error: {}", msg))
        }

        SovereignError::InternalError(msg) => Status::internal(msg),
    }
}
