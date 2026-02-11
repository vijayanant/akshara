use crate::base::error::{CryptoError, SovereignError};

#[test]
fn test_error_mapping() {
    let crypto_err = CryptoError::EncryptionFailed("test".to_string());
    let sov_err: SovereignError = crypto_err.into();
    assert!(matches!(sov_err, SovereignError::Crypto(_)));
}
