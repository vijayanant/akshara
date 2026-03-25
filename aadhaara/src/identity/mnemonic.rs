use crate::base::error::{AksharaError, IdentityError};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Generates a new cryptographically secure 24-word BIP-39 mnemonic.
pub fn generate_mnemonic() -> Result<String, AksharaError> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| AksharaError::Identity(IdentityError::MnemonicInvalid(e.to_string())))?;

    Ok(mnemonic.to_string())
}

/// Converts a BIP-39 mnemonic and optional passphrase into a 64-byte binary seed.
///
/// Implements NFKD normalization and PBKDF2-HMAC-SHA512 stretching (2048 iterations).
pub fn mnemonic_to_seed(
    phrase: &str,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, AksharaError> {
    let normalized = phrase.trim().to_lowercase();
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if words.len() != 24 {
        return Err(AksharaError::Identity(IdentityError::MnemonicInvalid(
            format!(
                "Akshara requires exactly 24 words for 256-bit entropy, but found {}. 12-word phrases are not permitted.",
                words.len()
            ),
        )));
    }

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(|e| AksharaError::Identity(IdentityError::MnemonicInvalid(e.to_string())))?;

    Ok(Zeroizing::new(mnemonic.to_seed(passphrase)))
}
