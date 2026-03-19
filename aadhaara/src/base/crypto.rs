use crate::base::error::{AksharaError, CryptoError};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use metrics::counter;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{Level, debug, error, span, trace};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- Signing Keys (Ed25519) ---

/// `SigningPublicKey` represents the public half of a user's signature authority.
///
/// We use Ed25519 because it is deterministic, high-performance, and resistant
/// to many side-channel attacks common in elliptic curve cryptography.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct SigningPublicKey([u8; 32]);

impl SigningPublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hex-encoded representation of the public key.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), AksharaError> {
        let span = span!(Level::TRACE, "signing_verify");
        let _enter = span.enter();

        let verifying_key = VerifyingKey::from_bytes(&self.0).map_err(|e| {
            AksharaError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid public key: {}",
                e
            )))
        })?;

        let ed_sig = EdSignature::from_slice(sig.as_bytes()).map_err(|e| {
            AksharaError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid signature format: {}",
                e
            )))
        })?;

        verifying_key.verify(msg, &ed_sig).map_err(|e| {
            debug!(error = %e, "Signature verification failed");
            counter!("akshara.crypto.verify_failure").increment(1);
            AksharaError::Crypto(CryptoError::InvalidSignature(e.to_string()))
        })?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey([u8; 32]);

impl std::fmt::Debug for SigningSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningSecretKey(<REDACTED>)")
    }
}

impl SigningSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// --- Encryption Keys (X25519) ---

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct EncryptionPublicKey([u8; 32]);

impl EncryptionPublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionSecretKey([u8; 32]);

impl std::fmt::Debug for EncryptionSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionSecretKey(<REDACTED>)")
    }
}

impl EncryptionSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// --- Symmetric Keys (XChaCha20) ---

/// `GraphKey` is the 256-bit symmetric key used to encrypt the content of a graph.
///
/// This key is the "Master Secret" for a specific document. Anyone with this key
/// can read every block in the graph. We use XChaCha20-Poly1305 to provide both
/// Confidentiality and Authenticated Integrity with extended 192-bit nonces.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GraphKey([u8; 32]);

impl std::fmt::Debug for GraphKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GraphKey(<REDACTED>)")
    }
}

impl GraphKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for GraphKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub trait AksharaSigner {
    fn sign(&self, message: &[u8]) -> Signature;
    fn public_key(&self) -> SigningPublicKey;
    fn derivation_path(&self) -> &str;
}

/// `BlockContent` holds the encrypted ciphertext and the extended nonce of a data block.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockContent {
    ciphertext: Vec<u8>,
    nonce: [u8; 24],
}

impl BlockContent {
    /// Encrypts plaintext using XChaCha20-Poly1305 with Associated Data.
    ///
    /// SAFETY: XChaCha20 uses a 192-bit (24-byte) nonce, which is large enough
    /// to be randomly generated without risk of collision for the lifetime
    /// of any graph.
    pub fn encrypt(
        plaintext: &[u8],
        key: &GraphKey,
        nonce_bytes: [u8; 24],
        associated_data: &[u8],
    ) -> Result<Self, AksharaError> {
        let span = span!(Level::TRACE, "content_encrypt");
        let _enter = span.enter();

        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
            error!(error = %e, "XChaCha20-Poly1305 encryption failed");
            AksharaError::Crypto(CryptoError::EncryptionFailed(format!(
                "XChaCha20 failed: {}",
                e
            )))
        })?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    pub fn decrypt(&self, key: &GraphKey, associated_data: &[u8]) -> Result<Vec<u8>, AksharaError> {
        let span = span!(Level::TRACE, "content_decrypt");
        let _enter = span.enter();

        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = XNonce::from_slice(&self.nonce);

        let payload = Payload {
            msg: self.ciphertext.as_slice(),
            aad: associated_data,
        };

        let plaintext = cipher.decrypt(nonce, payload).map_err(|e| {
            debug!(error = %e, "XChaCha20-Poly1305 decryption failed (AD or Key mismatch)");
            counter!("akshara.crypto.decryption_failure").increment(1);
            AksharaError::Crypto(CryptoError::DecryptionFailed(format!(
                "XChaCha20 failed: {}",
                e
            )))
        })?;

        Ok(plaintext)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Public-Crate API: Used by sibling crates for wire mapping.
    #[allow(dead_code)]
    pub(crate) fn from_raw_parts(ciphertext: Vec<u8>, nonce: [u8; 24]) -> Self {
        Self { ciphertext, nonce }
    }
}

/// `Lockbox` implements a Hybrid Encryption scheme (X25519 + XChaCha20-Poly1305).
///
/// It allows a sender to share a `GraphKey` with a specific recipient without
/// pre-sharing a secret. We use an ephemeral X25519 key for every lockbox
/// to ensure Forward Secrecy.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Lockbox {
    pub(crate) ephemeral_public_key: EncryptionPublicKey,
    pub(crate) content: BlockContent,
}

impl Lockbox {
    pub fn create(
        recipient_public: &EncryptionPublicKey,
        secret_to_lock: &GraphKey,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, AksharaError> {
        let span = span!(Level::DEBUG, "lockbox_create");
        let _enter = span.enter();

        let ephemeral_secret = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = XPublicKey::from(&ephemeral_secret);

        let recipient_xpub = XPublicKey::from(*recipient_public.as_bytes());

        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_xpub);
        let shared_key = GraphKey::new(*shared_secret.as_bytes());

        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        // LOCKBOX INVARIANT: Associated Data for a lockbox is the recipient's public key
        // to ensure the box cannot be replayed for another user.
        let ad = recipient_public.as_bytes();

        let content = BlockContent::encrypt(secret_to_lock.as_bytes(), &shared_key, nonce, ad)?;

        trace!("Lockbox created with ephemeral key");

        Ok(Self {
            ephemeral_public_key: EncryptionPublicKey::new(*ephemeral_public.as_bytes()),
            content,
        })
    }

    pub fn open(&self, recipient_secret: &EncryptionSecretKey) -> Result<GraphKey, AksharaError> {
        let span = span!(Level::DEBUG, "lockbox_open");
        let _enter = span.enter();

        let recipient_secret_scalar = StaticSecret::from(*recipient_secret.as_bytes());
        let ephemeral_public_point = XPublicKey::from(*self.ephemeral_public_key.as_bytes());

        let shared_secret = recipient_secret_scalar.diffie_hellman(&ephemeral_public_point);
        let shared_key = GraphKey::new(*shared_secret.as_bytes());

        // Re-derive recipient public key for AD verification
        let recipient_public_bytes =
            *XPublicKey::from(&StaticSecret::from(*recipient_secret.as_bytes())).as_bytes();
        let ad = &recipient_public_bytes;

        let decrypted_bytes = self.content.decrypt(&shared_key, ad).map_err(|e| {
            debug!(error = ?e, "Failed to decrypt lockbox content");
            e
        })?;

        let key_bytes: [u8; 32] = decrypted_bytes.try_into().map_err(|_| {
            error!("Decrypted key length mismatch");
            AksharaError::Crypto(CryptoError::InvalidKeyFormat(
                "Decrypted key is not 32 bytes".to_string(),
            ))
        })?;

        trace!("Lockbox opened successfully");

        Ok(GraphKey::new(key_bytes))
    }

    /// Public-Crate API: Used by sibling crates for wire mapping.
    #[allow(dead_code)]
    pub(crate) fn from_raw_parts(
        ephemeral_public_key: EncryptionPublicKey,
        content: BlockContent,
    ) -> Self {
        Self {
            ephemeral_public_key,
            content,
        }
    }
}
