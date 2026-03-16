use crate::base::address::GraphId;
use crate::base::crypto::{
    EncryptionPublicKey, EncryptionSecretKey, GraphKey, Signature, SigningPublicKey,
    SigningSecretKey, SovereignSigner,
};
use crate::base::error::SovereignError;
use crate::identity::{derivation, mnemonic, paths};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// `Identity` represents the public profile of an Akshara user.
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

/// `SecretIdentity` is a functional credential derived for a specific path.
pub struct SecretIdentity {
    pub(crate) signing_key: SigningSecretKey,
    pub(crate) encryption_key: EncryptionSecretKey,
    pub(crate) public: Identity,
    pub(crate) derivation_path: String,
}

impl std::fmt::Debug for SecretIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretIdentity")
            .field("public", &self.public)
            .field("derivation_path", &self.derivation_path)
            .field("signing_key", &"<REDACTED>")
            .field("encryption_key", &"<REDACTED>")
            .finish()
    }
}

/// `MasterIdentity` is a transient container for the root entropy.
pub struct MasterIdentity {
    pub(crate) seed: Zeroizing<[u8; 64]>,
}

impl std::fmt::Debug for MasterIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterIdentity(<REDACTED>)")
    }
}

/// `PreKeyBundle` is a collection of signed, one-time-use encryption keys.
///
/// It is stored on the Relay to facilitate asynchronous handshakes with offline recipients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// The public identity of the device that owns these pre-keys.
    pub device_identity: Identity,
    /// A map of index -> Public Encryption Key (X25519).
    pub pre_keys: BTreeMap<u32, EncryptionPublicKey>,
    /// A signature over the canonical bytes of (device_identity + pre_keys).
    pub signature: Signature,
}

impl MasterIdentity {
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, SovereignError> {
        let seed = mnemonic::mnemonic_to_seed(phrase, passphrase)?;
        Ok(Self { seed })
    }

    pub fn derive_child(&self, path: &str) -> Result<SecretIdentity, SovereignError> {
        let signing_key = derivation::derive_slip0010_key(&self.seed, path)?;
        Ok(SecretIdentity::from_signing_key_at_path(
            signing_key,
            path.to_string(),
        ))
    }

    /// Derives a 32-byte shared vault secret for the Internal Keyring (Branch 4).
    pub fn derive_keyring_secret(&self, version: u32) -> Result<[u8; 32], SovereignError> {
        let path = crate::identity::paths::format_keyring_path(version);
        let signing_key = derivation::derive_slip0010_key(&self.seed, &path)?;
        Ok(signing_key.to_bytes())
    }

    /// Derives an isolated, anonymous Discovery ID for a specific graph.
    ///
    /// Matches Spec v0.1.0-alpha (Hardened):
    /// 1. Derive DiscoveryMasterKey from Branch 5 (m/44'/999'/0'/5'/0').
    /// 2. DiscoveryId = HMAC-SHA256(DiscoveryMasterKey, "akshara.v1.discovery" + GraphId).
    pub fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<GraphId, SovereignError> {
        // 1. Derive the stable Branch 5 Discovery Key
        let path = crate::identity::paths::format_akshara_path(
            crate::identity::paths::BRANCH_DISCOVERY,
            0,
        );
        let discovery_master_key = derivation::derive_slip0010_key(&self.seed, &path)?;

        // 2. Derive the isolated Discovery ID via HMAC-SHA256
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&discovery_master_key.to_bytes())
            .map_err(|e| {
                SovereignError::InternalError(format!("HMAC initialization failed: {}", e))
            })?;

        hmac.update(b"akshara.v1.discovery");
        hmac.update(graph_id.as_bytes());

        let result = hmac.finalize().into_bytes();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&result[..16]);

        Ok(GraphId::from_bytes(uuid_bytes))
    }

    /// Generates a Pre-Key Bundle for a specific device index.
    pub fn generate_pre_key_bundle(
        &self,
        device_index: u32,
        start_index: u32,
        count: u32,
    ) -> Result<PreKeyBundle, SovereignError> {
        let device_path = paths::format_akshara_path(paths::BRANCH_EXECUTIVE, device_index);
        let device_secret = self.derive_child(&device_path)?;

        let mut pre_keys = BTreeMap::new();
        for i in 0..count {
            let index = start_index + i;
            let path = format!(
                "m/{}'/{}'/0'/{}'/{}'/{}'",
                paths::PURPOSE_AKSHARA,
                paths::COIN_TYPE_AKSHARA,
                paths::BRANCH_HANDSHAKE,
                device_index,
                index
            );
            let child = self.derive_child(&path)?;
            pre_keys.insert(index, child.public().encryption_key().clone());
        }

        // AKSHARA RITUAL: Canonicalize and sign the bundle
        let mut data_to_sign = crate::base::encoding::to_canonical_bytes(&device_secret.public)?;
        data_to_sign.extend(crate::base::encoding::to_canonical_bytes(&pre_keys)?);

        let signature = device_secret.sign(&data_to_sign);

        Ok(PreKeyBundle {
            device_identity: device_secret.public().clone(),
            pre_keys,
            signature,
        })
    }
}

impl SecretIdentity {
    pub fn generate(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mnemonic = mnemonic::generate_mnemonic().unwrap();
        Self::from_mnemonic(mnemonic.as_str(), "").unwrap()
    }

    /// Derives a shared vault secret from a mnemonic and version.
    pub fn derive_keyring_secret(
        phrase: &str,
        passphrase: &str,
        version: u32,
    ) -> Result<[u8; 32], SovereignError> {
        let master = MasterIdentity::from_mnemonic(phrase, passphrase)?;
        master.derive_keyring_secret(version)
    }

    pub fn generate_mnemonic() -> Result<String, SovereignError> {
        mnemonic::generate_mnemonic()
    }

    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, SovereignError> {
        Self::from_mnemonic_at_path(phrase, passphrase, "m/44'/999'/0'/0'/0'")
    }

    pub fn from_mnemonic_at_path(
        phrase: &str,
        passphrase: &str,
        path: &str,
    ) -> Result<Self, SovereignError> {
        let master = MasterIdentity::from_mnemonic(phrase, passphrase)?;
        master.derive_child(path)
    }

    pub(crate) fn from_signing_key_at_path(signing_key: SigningKey, path: String) -> Self {
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
            derivation_path: path,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_signing_key(signing_key: SigningKey) -> Self {
        Self::from_signing_key_at_path(signing_key, "unknown".to_string())
    }

    pub fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey, SovereignError> {
        let mut hmac =
            Hmac::<Sha512>::new_from_slice(self.signing_key.as_bytes()).map_err(|e| {
                SovereignError::InternalError(format!("HMAC initialization failed: {}", e))
            })?;

        hmac.update(b"akshara.v1.graph_key");
        hmac.update(graph_id.as_bytes());

        let output = hmac.finalize().into_bytes();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&output[0..32]);

        Ok(GraphKey::from(key_bytes))
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

impl PreKeyBundle {
    /// Verifies the integrity and authority of the bundle.
    pub fn verify(&self) -> Result<(), SovereignError> {
        let mut data_to_verify = crate::base::encoding::to_canonical_bytes(&self.device_identity)?;
        data_to_verify.extend(crate::base::encoding::to_canonical_bytes(&self.pre_keys)?);

        self.device_identity
            .signing_key()
            .verify(&data_to_verify, &self.signature)
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

    fn derivation_path(&self) -> &str {
        &self.derivation_path
    }
}
