use crate::base::error::{AksharaError, IdentityError};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use zeroize::{Zeroize, Zeroizing};

/// Implements SLIP-0010 Hardened Derivation for Ed25519.
///
/// This is the mathematical engine of the Akshara Identity tree. It follows
/// the strict recursive HMAC-SHA512 standard to derive isolated child keys
/// from a 64-byte master seed.
pub fn derive_slip0010_key(seed: &[u8; 64], path: &str) -> Result<SigningKey, AksharaError> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
        .map_err(|e| AksharaError::InternalError(e.to_string()))?;
    hmac.update(seed);
    let mut output = hmac.finalize().into_bytes();

    let mut current_key = Zeroizing::new([0u8; 32]);
    let mut current_chain = Zeroizing::new([0u8; 32]);
    current_key.copy_from_slice(&output[0..32]);
    current_chain.copy_from_slice(&output[32..64]);
    output.zeroize();

    let segments = path.split('/').collect::<Vec<_>>();
    if segments[0] != "m" {
        return Err(AksharaError::Identity(IdentityError::DerivationFailed(
            "Derivation path must start with m".into(),
        )));
    }

    for segment in &segments[1..] {
        let index = if let Some(stripped) = segment.strip_suffix('\'') {
            stripped.parse::<u32>().map_err(|_| {
                AksharaError::Identity(IdentityError::DerivationFailed(format!(
                    "Invalid index segment: {}",
                    segment
                )))
            })? + 0x8000_0000
        } else {
            // Ed25519 ONLY supports hardened derivation to prevent public-parent-to-private-child leakage.
            return Err(AksharaError::Identity(IdentityError::DerivationFailed(
                "Ed25519 only supports hardened derivation indices (e.g. 0')".into(),
            )));
        };

        let mut hmac = Hmac::<Sha512>::new_from_slice(current_chain.as_slice())
            .map_err(|e| AksharaError::InternalError(e.to_string()))?;

        // SLIP-0010 Hardened Step: [0x00] || [ParentKey] || [Index]
        hmac.update(&[0x00]);
        hmac.update(current_key.as_slice());
        hmac.update(&index.to_be_bytes());
        let mut output = hmac.finalize().into_bytes();

        current_key.copy_from_slice(&output[0..32]);
        current_chain.copy_from_slice(&output[32..64]);
        output.zeroize();
    }

    Ok(SigningKey::from_bytes(
        current_key.as_slice().try_into().unwrap(),
    ))
}
