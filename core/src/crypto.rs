use crate::error::SovereignError;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{Level, debug, error, span, trace};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- Signing Keys (Ed25519) ---

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

        let verifying_key = VerifyingKey::from_bytes(&self.0)
            .map_err(|e| SovereignError::Unauthorized(format!("Invalid public key: {}", e)))?;

        let ed_sig = EdSignature::from_slice(sig.as_bytes()).map_err(|e| {
            SovereignError::Unauthorized(format!("Invalid signature format: {}", e))
        })?;

        verifying_key.verify(msg, &ed_sig).map_err(|e| {
            debug!(error = %e, "Signature verification failed");
            SovereignError::Unauthorized(format!("Signature verification failed: {}", e))
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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionSecretKey([u8; 32]);

impl EncryptionSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// --- Symmetric Keys (AES-256) ---

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DocKey([u8; 32]);

impl DocKey {
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

impl From<[u8; 32]> for DocKey {
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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockContent {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

impl BlockContent {
    pub fn encrypt(
        plaintext: &[u8],
        key: &DocKey,
        nonce_bytes: [u8; 12],
    ) -> Result<Self, SovereignError> {
        let span = span!(Level::TRACE, "content_encrypt");
        let _enter = span.enter();

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            error!(error = %e, "AES-GCM encryption failed");
            SovereignError::EncryptionError(format!("AES-GCM failed: {}", e))
        })?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    pub fn decrypt(&self, key: &DocKey) -> Result<Vec<u8>, SovereignError> {
        let span = span!(Level::TRACE, "content_decrypt");
        let _enter = span.enter();

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| {
                debug!(error = %e, "AES-GCM decryption failed");
                SovereignError::DecryptionError(format!("AES-GCM failed: {}", e))
            })?;

        Ok(plaintext)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
}

/// A container for an encrypted key, including the ephemeral public key used to lock it.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Lockbox {
    pub ephemeral_public_key: EncryptionPublicKey,
    pub content: BlockContent,
}

impl Lockbox {
    pub fn create(
        recipient_public: &EncryptionPublicKey,
        secret_to_lock: &DocKey,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, SovereignError> {
        let span = span!(Level::DEBUG, "lockbox_create");
        let _enter = span.enter();

        // Generate an ephemeral keypair for this specific lockbox
        let ephemeral_secret = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = XPublicKey::from(&ephemeral_secret);

        let recipient_xpub = XPublicKey::from(*recipient_public.as_bytes());

        // Calculate shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_xpub);

        let shared_key = DocKey::new(*shared_secret.as_bytes());

        // Use shared secret to encrypt the master secret (doc_key)
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let content = BlockContent::encrypt(secret_to_lock.as_bytes(), &shared_key, nonce)?;

        trace!("Lockbox created with ephemeral key");

        Ok(Self {
            ephemeral_public_key: EncryptionPublicKey::new(*ephemeral_public.as_bytes()),
            content,
        })
    }

    pub fn open(&self, recipient_secret: &EncryptionSecretKey) -> Result<DocKey, SovereignError> {
        let span = span!(Level::DEBUG, "lockbox_open");
        let _enter = span.enter();

        let recipient_secret_scalar = StaticSecret::from(*recipient_secret.as_bytes());
        let ephemeral_public_point = XPublicKey::from(*self.ephemeral_public_key.as_bytes());

        // Calculate shared secret: RecipientPriv + EphemeralPub
        let shared_secret = recipient_secret_scalar.diffie_hellman(&ephemeral_public_point);
        let shared_key = DocKey::new(*shared_secret.as_bytes());

        // Decrypt the key
        let decrypted_bytes = self.content.decrypt(&shared_key).map_err(|e| {
            debug!(error = %e, "Failed to decrypt lockbox content");
            e
        })?;

        let key_bytes: [u8; 32] = decrypted_bytes.try_into().map_err(|_| {
            error!("Decrypted key length mismatch");
            SovereignError::SerializationError("Decrypted key is not 32 bytes".to_string())
        })?;

        trace!("Lockbox opened successfully");

        Ok(DocKey::new(key_bytes))
    }
}
