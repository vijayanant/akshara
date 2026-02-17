use crate::base::error::{CryptoError, SovereignError};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
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

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SovereignError> {
        let span = span!(Level::TRACE, "signing_verify");
        let _enter = span.enter();

        let verifying_key = VerifyingKey::from_bytes(&self.0).map_err(|e| {
            SovereignError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid public key: {}",
                e
            )))
        })?;

        let ed_sig = EdSignature::from_slice(sig.as_bytes()).map_err(|e| {
            SovereignError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid signature format: {}",
                e
            )))
        })?;

        verifying_key.verify(msg, &ed_sig).map_err(|e| {
            debug!(error = %e, "Signature verification failed");
            counter!("sovereign.crypto.verify_failure").increment(1);
            SovereignError::Crypto(CryptoError::InvalidSignature(e.to_string()))
        })?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey([u8; 32]);

impl SigningSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionSecretKey([u8; 32]);

impl EncryptionSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// --- Symmetric Keys (AES-256) ---

/// `GraphKey` is the AES-256 symmetric key used to encrypt the content of a graph.
///
/// This key is the "Master Secret" for a specific document. Anyone with this key
/// can read every block in the graph. We use AES-256-GCM to provide both
/// Confidentiality and Authenticated Integrity.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GraphKey([u8; 32]);

impl GraphKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
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

pub trait SovereignSigner {
    fn sign(&self, message: &[u8]) -> Signature;
    fn public_key(&self) -> SigningPublicKey;
}

/// `BlockContent` holds the encrypted ciphertext and the nonce of a data block.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockContent {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

impl BlockContent {
    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// SAFETY: Every encryption operation MUST use a unique nonce.
    /// Reusing a nonce with the same key allows an attacker to XOR two ciphertexts
    /// and recover the plaintext (The "Forbidden Attack").
    pub fn encrypt(
        plaintext: &[u8],
        key: &GraphKey,
        nonce_bytes: [u8; 12],
    ) -> Result<Self, SovereignError> {
        let span = span!(Level::TRACE, "content_encrypt");
        let _enter = span.enter();

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            error!(error = %e, "AES-GCM encryption failed");
            SovereignError::Crypto(CryptoError::EncryptionFailed(format!(
                "AES-GCM failed: {}",
                e
            )))
        })?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    pub fn decrypt(&self, key: &GraphKey) -> Result<Vec<u8>, SovereignError> {
        let span = span!(Level::TRACE, "content_decrypt");
        let _enter = span.enter();

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| {
                debug!(error = %e, "AES-GCM decryption failed");
                counter!("sovereign.crypto.decryption_failure").increment(1);
                SovereignError::Crypto(CryptoError::DecryptionFailed(format!(
                    "AES-GCM failed: {}",
                    e
                )))
            })?;

        Ok(plaintext)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    #[allow(dead_code)]
    pub(crate) fn from_raw_parts(ciphertext: Vec<u8>, nonce: [u8; 12]) -> Self {
        Self { ciphertext, nonce }
    }
}

/// `Lockbox` implements a Hybrid Encryption scheme (X25519 + AES-GCM).
///
/// It allows a sender to share a `GraphKey` with a specific recipient without
/// pre-sharing a secret. We use an ephemeral X25519 key for every lockbox
/// to ensure that if the sender's master key is compromised, previous
/// lockboxes cannot be decrypted (Forward Secrecy).
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
    ) -> Result<Self, SovereignError> {
        let span = span!(Level::DEBUG, "lockbox_create");
        let _enter = span.enter();

        let ephemeral_secret = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = XPublicKey::from(&ephemeral_secret);

        let recipient_xpub = XPublicKey::from(*recipient_public.as_bytes());

        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_xpub);
        let shared_key = GraphKey::new(*shared_secret.as_bytes());

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let content = BlockContent::encrypt(secret_to_lock.as_bytes(), &shared_key, nonce)?;

        trace!("Lockbox created with ephemeral key");

        Ok(Self {
            ephemeral_public_key: EncryptionPublicKey::new(*ephemeral_public.as_bytes()),
            content,
        })
    }

    pub fn open(&self, recipient_secret: &EncryptionSecretKey) -> Result<GraphKey, SovereignError> {
        let span = span!(Level::DEBUG, "lockbox_open");
        let _enter = span.enter();

        let recipient_secret_scalar = StaticSecret::from(*recipient_secret.as_bytes());
        let ephemeral_public_point = XPublicKey::from(*self.ephemeral_public_key.as_bytes());

        let shared_secret = recipient_secret_scalar.diffie_hellman(&ephemeral_public_point);
        let shared_key = GraphKey::new(*shared_secret.as_bytes());

        let decrypted_bytes = self.content.decrypt(&shared_key).map_err(|e| {
            debug!(error = ?e, "Failed to decrypt lockbox content");
            e
        })?;

        let key_bytes: [u8; 32] = decrypted_bytes.try_into().map_err(|_| {
            error!("Decrypted key length mismatch");
            SovereignError::Crypto(CryptoError::InvalidKeyFormat(
                "Decrypted key is not 32 bytes".to_string(),
            ))
        })?;

        trace!("Lockbox opened successfully");

        Ok(GraphKey::new(key_bytes))
    }

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
