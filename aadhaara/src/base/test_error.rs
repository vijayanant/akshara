use crate::base::address::{Address, BlockId};
use crate::base::error::{
    CryptoError, IdentityError, IntegrityError, ProtocolError, SovereignError, StoreError,
};

#[test]
fn test_error_mapping() {
    let crypto_err = CryptoError::EncryptionFailed("test".to_string());
    let sov_err: SovereignError = crypto_err.into();
    assert!(matches!(sov_err, SovereignError::Crypto(_)));

    // Test error display
    let crypto_err = SovereignError::Crypto(CryptoError::EncryptionFailed("test".to_string()));
    assert!(crypto_err.to_string().contains("Encryption"));

    let integrity_err = SovereignError::Integrity(IntegrityError::MalformedId);
    assert!(integrity_err.to_string().contains("malformed"));

    let identity_err =
        SovereignError::Identity(IdentityError::DerivationFailed("test".to_string()));
    assert!(identity_err.to_string().contains("derivation"));

    let store_err = SovereignError::Store(StoreError::NotFound("test".to_string()));
    assert!(store_err.to_string().contains("not found"));

    let protocol_err = SovereignError::Protocol(ProtocolError::TooManyHeads(100));
    assert!(protocol_err.to_string().contains("100"));

    let internal_err = SovereignError::InternalError("test".to_string());
    assert!(internal_err.to_string().contains("test"));
}

#[test]
fn test_error_from_conversions() {
    // Test that From<> conversions work correctly
    let crypto_err = CryptoError::DecryptionFailed("test".to_string());
    let sovereign: SovereignError = crypto_err.into();
    assert!(matches!(sovereign, SovereignError::Crypto(_)));

    let integrity_err =
        IntegrityError::CycleDetected(Address::from(BlockId::from_sha256(&[1u8; 32])));
    let sovereign: SovereignError = integrity_err.into();
    assert!(matches!(sovereign, SovereignError::Integrity(_)));

    let identity_err = IdentityError::MnemonicInvalid("test".to_string());
    let sovereign: SovereignError = identity_err.into();
    assert!(matches!(sovereign, SovereignError::Identity(_)));

    let store_err = StoreError::IoError("test".to_string());
    let sovereign: SovereignError = store_err.into();
    assert!(matches!(sovereign, SovereignError::Store(_)));

    let protocol_err = ProtocolError::DeltaTooLarge(1000);
    let sovereign: SovereignError = protocol_err.into();
    assert!(matches!(sovereign, SovereignError::Protocol(_)));
}
