use crate::base::address::GraphId;
use crate::base::crypto::{
    EncryptionPublicKey, EncryptionSecretKey, GraphKey, Signature, SigningPublicKey,
    SigningSecretKey, SovereignSigner,
};
use crate::base::error::{IdentityError, SovereignError};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use metrics::{counter, histogram};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use tracing::{Level, debug, error, info, span, trace};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// `Identity` represents the public profile of a Sovereign user.
///
/// It binds a Signing key (for provenance) and an Encryption key (for privacy)
/// into a single unit. This allows other users to both verify a user's
/// messages and send them encrypted data using only their public identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub(crate) signing_key: SigningPublicKey,
    pub(crate) encryption_key: EncryptionPublicKey,
}

impl Identity {
    pub fn new(signing_key: SigningPublicKey, encryption_key: EncryptionPublicKey) -> Self {
        Self {
            signing_key,
            encryption_key,
        }
    }

    pub fn signing_key(&self) -> &SigningPublicKey {
        &self.signing_key
    }

    pub fn encryption_key(&self) -> &EncryptionPublicKey {
        &self.encryption_key
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verify(message, signature).is_ok()
    }
}

/// `SecretIdentity` is the root of a user's sovereignty.
///
/// It holds the private keys derived from the master seed. In Sovereign,
/// all document keys are deterministically derived from this secret,
/// ensuring that a user can recover their entire digital life using only
/// their 24-word mnemonic (Akshara).
pub struct SecretIdentity {
    pub(crate) signing_key: SigningSecretKey,
    pub(crate) encryption_key: EncryptionSecretKey,
    pub(crate) public: Identity,
}

impl SecretIdentity {
    /// Generates a fresh random identity (24-word entropy equivalent).
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let span = span!(Level::DEBUG, "identity_generate");
        let _enter = span.enter();

        let signing_key = SigningKey::generate(rng);
        counter!("sovereign.identity.generated").increment(1);

        Self::from_signing_key(signing_key)
    }

    /// Generates a new valid 24-word BIP-39 mnemonic phrase.
    pub fn generate_mnemonic() -> Result<String, SovereignError> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
            error!(error = %e, "Failed to generate mnemonic entropy");
            SovereignError::Identity(IdentityError::MnemonicInvalid(format!(
                "Entropy failure: {}",
                e
            )))
        })?;

        Ok(mnemonic.to_string())
    }

    /// Derives an identity from a BIP-39 mnemonic using the SLIP-0010 standard.
    ///
    /// We use SLIP-0010 for Ed25519 derivation because it ensures that the
    /// resulting keys are compatible with industry-standard hardware wallets
    /// and recovery procedures.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, SovereignError> {
        // High-level span for the entire recovery process
        let span = span!(Level::INFO, "identity_rebirth");
        let _enter = span.enter();
        let start_time = std::time::Instant::now();

        let normalized = phrase.trim().to_lowercase();
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| {
                debug!(error = %e, "Mnemonic validation failed - possible user typo");
                SovereignError::Identity(IdentityError::MnemonicInvalid(e.to_string()))
            })?;

        let seed = mnemonic.to_seed(passphrase);

        let mut hmac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        hmac.update(&seed);
        let output = hmac.finalize().into_bytes();

        let mut master_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        master_key.copy_from_slice(&output[0..32]);
        chain_code.copy_from_slice(&output[32..64]);

        // Derivation Path: m/44'/999'/0'/0'/0'
        // 44' = Purpose (BIP-44)
        // 999' = Coin Type (Sovereign)
        // 0'/0'/0' = Account/Change/Index
        let path: [u32; 5] = [
            44 + 0x8000_0000,
            999 + 0x8000_0000,
            0x8000_0000,
            0x8000_0000,
            0x8000_0000,
        ];

        let mut current_key = master_key;
        let mut current_chain = chain_code;

        // Trace each step of the derivation path for mathematical audit
        for (i, index) in path.iter().enumerate() {
            trace!(level = i, derivation_index = %index, "Deriving child key");
            let mut hmac = Hmac::<Sha512>::new_from_slice(&current_chain)
                .map_err(|e| SovereignError::InternalError(e.to_string()))?;
            hmac.update(&[0x00]);
            hmac.update(&current_key);
            hmac.update(&index.to_be_bytes());
            let output = hmac.finalize().into_bytes();

            current_key.copy_from_slice(&output[0..32]);
            current_chain.copy_from_slice(&output[32..64]);
        }

        let signing_key = SigningKey::from_bytes(&current_key);

        let elapsed = start_time.elapsed();
        histogram!("sovereign.identity.rebirth_latency").record(elapsed);
        counter!("sovereign.identity.rebirth_success").increment(1);

        info!(
            latency_ms = elapsed.as_millis(),
            "Identity successfully rebirthed from mnemonic"
        );

        Ok(Self::from_signing_key(signing_key))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let signing_public = signing_key.verifying_key();
        let encryption_secret = StaticSecret::from(signing_key.to_bytes());
        let encryption_public = XPublicKey::from(&encryption_secret);

        let public_id = Identity::new(
            SigningPublicKey::new(signing_public.to_bytes()),
            EncryptionPublicKey::new(*encryption_public.as_bytes()),
        );

        Self {
            signing_key: SigningSecretKey::new(signing_key.to_bytes()),
            encryption_key: EncryptionSecretKey::new(encryption_secret.to_bytes()),
            public: public_id,
        }
    }

    /// Derives a stable, private GraphId used to locate the user's data on a Relay.
    ///
    /// This allows a user to "blindly" find their data on a relay without
    /// the relay knowing their public identity.
    #[allow(dead_code)] // Public-Crate API: Used by sibling crates for blind discovery.
    pub(crate) fn derive_discovery_id(&self) -> GraphId {
        let span = span!(Level::DEBUG, "derive_discovery_id");
        let _enter = span.enter();

        let mut hmac = Hmac::<Sha512>::new_from_slice(self.signing_key.as_bytes())
            .expect("HMAC must accept 32-byte Ed25519 key");
        hmac.update(b"sovereign.v1.discovery");

        let output = hmac.finalize().into_bytes();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&output[..16]);

        let id = GraphId::from_bytes(uuid_bytes);
        trace!(discovery_id = ?id, "Stable discovery identifier derived");
        id
    }

    /// Derives a deterministic 32-byte GraphKey for a specific graph.
    ///
    /// By binding the `graph_id` into the key derivation, we ensure that
    /// compromise of one document key does not compromise others (Key Isolation).
    pub fn derive_graph_key(&self, graph_id: &GraphId) -> GraphKey {
        let span = span!(Level::DEBUG, "derive_graph_key", graph_id = ?graph_id);
        let _enter = span.enter();

        let mut hmac = Hmac::<Sha512>::new_from_slice(self.signing_key.as_bytes())
            .expect("HMAC must accept 32-byte Ed25519 key");

        hmac.update(b"sovereign.v1.graph_key");
        hmac.update(graph_id.as_bytes());

        let output = hmac.finalize().into_bytes();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&output[0..32]);

        counter!("sovereign.identity.graph_key_derived").increment(1);
        GraphKey::from(key_bytes)
    }

    pub fn signing_key(&self) -> &SigningSecretKey {
        &self.signing_key
    }

    pub fn public(&self) -> &Identity {
        &self.public
    }

    pub fn encryption_key(&self) -> &EncryptionSecretKey {
        &self.encryption_key
    }
}

impl SovereignSigner for SecretIdentity {
    fn sign(&self, message: &[u8]) -> Signature {
        let key = SigningKey::from_bytes(self.signing_key.as_bytes());
        let sig = key.sign(message);
        Signature::new(sig.to_vec())
    }

    fn public_key(&self) -> SigningPublicKey {
        self.public.signing_key().clone()
    }
}

#[cfg(test)]
mod test_identity;

#[cfg(test)]
mod test_identity_graph;

#[cfg(test)]
mod test_identity_protocol;
