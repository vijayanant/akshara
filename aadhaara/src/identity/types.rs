use crate::base::address::{GraphId, Lakshana};
use crate::base::crypto::{
    AksharaSigner, EncryptionPublicKey, EncryptionSecretKey, GraphKey, Signature, SigningPublicKey,
    SigningSecretKey,
};
use crate::base::error::AksharaError;
use crate::identity::{derivation, mnemonic, paths};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
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
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretIdentity {
    pub(crate) signing_key: SigningSecretKey,
    pub(crate) encryption_key: EncryptionSecretKey,
    #[zeroize(skip)]
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

/// `ShadowCertificate` provides mathematical proof that a Master Executive key
/// has authorized a specific Shadow Key for a specific Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCertificate {
    /// The Master Executive public key that granted the authority.
    pub master_public_key: SigningPublicKey,
    /// A signature by the master key over (ShadowPublicKey + GraphId).
    pub signature: Signature,
}

/// `GraphDescriptor` contains the metadata and encrypted key for a specific graph.
///
/// It is stored in the Identity Graph under `/resources/` to enable
/// deterministic recovery of the user's world from their 24 words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphDescriptor {
    /// The stable 128-bit identifier of the graph.
    pub graph_id: GraphId,
    /// A human-readable label (e.g., "Work Notes").
    pub label: Option<String>,
    /// The GraphKey encrypted with the user's Keyring Secret (Branch 4).
    pub enc_graph_key: crate::base::crypto::BlockContent,
    /// The version of the keyring secret used for encryption.
    pub keyring_version: u64,
    /// The Unix timestamp of registration (informational).
    pub created_at: i64,
    /// If shared, the Master Executive public key of the sharer.
    pub shared_by: Option<SigningPublicKey>,
}

impl GraphDescriptor {
    pub fn decrypt_key(&self, keyring_secret: &GraphKey) -> Result<GraphKey, AksharaError> {
        let plaintext = self
            .enc_graph_key
            .decrypt(keyring_secret, self.graph_id.as_bytes())?;

        let bytes: [u8; 32] = plaintext.try_into().map_err(|_| {
            AksharaError::Crypto(crate::base::error::CryptoError::InvalidKeyFormat(
                "Decrypted key is not 32 bytes".to_string(),
            ))
        })?;

        Ok(GraphKey::new(bytes))
    }
}

impl MasterIdentity {
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, AksharaError> {
        let seed = mnemonic::mnemonic_to_seed(phrase, passphrase)?;
        Ok(Self { seed })
    }

    pub fn derive_child(
        &self,
        path: &str,
        graph_id: Option<&GraphId>,
    ) -> Result<SecretIdentity, AksharaError> {
        let mut signing_key = derivation::derive_slip0010_key(&self.seed, path)?;

        // SHADOW IDENTITY RITUAL (Privacy Preservation):
        // If a GraphId is provided, we perform an additional HMAC-SHA256 step to
        // isolate the key to this specific graph. This prevents "clustering" attacks
        // where a Relay can link the same author across different graphs.
        if let Some(gid) = graph_id {
            // AKSHARA RITUAL: Use the SECRET key as the HMAC key to ensure the shadow
            // identity is actually a secret that cannot be forged by observers.
            let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&signing_key.to_bytes())
                .map_err(|e| AksharaError::InternalError(format!("HMAC init failed: {}", e)))?;
            hmac.update(b"akshara.v1.shadow_identity");
            hmac.update(gid.as_bytes());
            let result = hmac.finalize().into_bytes();
            let mut shadow_seed = [0u8; 32];
            shadow_seed.copy_from_slice(&result[..32]);

            // Re-derive a valid SigningKey from the secret HMAC output
            signing_key = SigningKey::from_bytes(&shadow_seed);
        }

        Ok(SecretIdentity::from_signing_key_at_path(
            signing_key,
            path.to_string(),
        ))
    }

    /// Derives a 32-byte shared vault secret for the Internal Keyring (Branch 4).
    pub fn derive_keyring_secret(&self, version: u32) -> Result<GraphKey, AksharaError> {
        let path = crate::identity::paths::format_keyring_path(version);
        let signing_key = derivation::derive_slip0010_key(&self.seed, &path)?;
        Ok(GraphKey::new(*signing_key.verifying_key().as_bytes()))
    }

    /// Derives an isolated, anonymous Discovery ID (Lakshana) for a specific graph.
    ///
    /// Matches Spec v0.1.0-alpha (Hardened):
    /// 1. Derive DiscoveryMasterKey from Branch 5 (m/44'/999'/0'/5'/0').
    /// 2. Lakshana = HMAC-SHA256(DiscoveryMasterKey, "akshara.v1.discovery" + GraphId).
    pub fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana, AksharaError> {
        let mut hmac = self.init_discovery_hmac()?;
        hmac.update(graph_id.as_bytes());

        let result = hmac.finalize().into_bytes();
        let mut lakshana_bytes = [0u8; 32];
        lakshana_bytes.copy_from_slice(&result[..32]);

        Ok(Lakshana::new(lakshana_bytes))
    }

    /// Derives the root Identity Lakshana for finding the user's own Identity Graph.
    pub fn derive_identity_lakshana(&self) -> Result<Lakshana, AksharaError> {
        let hmac = self.init_discovery_hmac()?;
        let result = hmac.finalize().into_bytes();
        let mut lakshana_bytes = [0u8; 32];
        lakshana_bytes.copy_from_slice(&result[..32]);

        Ok(Lakshana::new(lakshana_bytes))
    }

    /// Derives the stable Identity ID (GraphId) for the user's own Identity Graph.
    pub fn identity_id(&self) -> Result<GraphId, AksharaError> {
        // RITUAL: Identity_ID = Hash("akshara.v1.identity" || Master_Public_Key)
        let master_path = "m/44'/999'/0'/0'/0'";
        let master_key = derivation::derive_slip0010_key(&self.seed, master_path)?;
        let master_pub = master_key.verifying_key();

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"akshara.v1.identity");
        hasher.update(master_pub.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&result[..16]);
        Ok(GraphId::from_bytes(bytes))
    }

    /// High-level ritual to register a graph in the user's Identity Graph.
    ///
    /// This encapsulates:
    /// 1. Deriving the Keyring Secret (Branch 4).
    /// 2. Encrypting the GraphKey.
    /// 3. Constructing the Descriptor.
    /// 4. Updating the Merkle-Index in the store.
    pub async fn register_resource(
        &self,
        store: &impl crate::state::store::GraphStore,
        graph_id: GraphId,
        graph_key: &GraphKey,
        label: Option<String>,
        is_owned: bool,
    ) -> Result<crate::base::address::ManifestId, AksharaError> {
        let id_graph_id = self.identity_id()?;
        let legislator = self.derive_child("m/44'/999'/0'/0'/0'", None)?;
        let keyring_secret = self.derive_keyring_secret(0)?;

        let mut rng = rand::rngs::OsRng;
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let descriptor = GraphDescriptor {
            graph_id,
            label,
            enc_graph_key: crate::base::crypto::BlockContent::encrypt(
                graph_key.as_bytes(),
                &keyring_secret,
                nonce,
                graph_id.as_bytes(),
            )?,
            keyring_version: 0,
            created_at: 0,   // Rebirth Invariant: set to 0 for bit-permanence
            shared_by: None, // TODO: Support shared_by in future
        };

        let executive = self.derive_child("m/44'/999'/0'/1'/0'", None)?;
        let executive_pub = executive.public().signing_key().clone();

        let id_graph = crate::identity::graph::IdentityGraph::new(store);
        id_graph
            .add_resource(
                descriptor,
                is_owned,
                &id_graph_id,
                &legislator,
                &executive_pub,
            )
            .await
    }

    fn init_discovery_hmac(&self) -> Result<Hmac<sha2::Sha256>, AksharaError> {
        // 1. Derive the stable Branch 5 Discovery Key
        let path = crate::identity::paths::format_akshara_path(
            crate::identity::paths::BRANCH_DISCOVERY,
            0,
        );
        let discovery_master_key = derivation::derive_slip0010_key(&self.seed, &path)?;

        // 2. Initialize HMAC-SHA256 with domain separator
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&discovery_master_key.to_bytes())
            .map_err(|e| {
                AksharaError::InternalError(format!("HMAC initialization failed: {}", e))
            })?;

        hmac.update(b"akshara.v1.discovery");
        Ok(hmac)
    }

    /// Generates a Pre-Key Bundle for a specific device index.
    pub fn generate_pre_key_bundle(
        &self,
        device_index: u32,
        start_index: u32,
        count: u32,
    ) -> Result<PreKeyBundle, AksharaError> {
        let device_path = paths::format_akshara_path(paths::BRANCH_EXECUTIVE, device_index);
        let device_secret = self.derive_child(&device_path, None)?;

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
            let child = self.derive_child(&path, None)?;
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
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self, AksharaError> {
        let mnemonic = mnemonic::generate_mnemonic_with_rng(rng)?;
        let mnemonic = zeroize::Zeroizing::new(mnemonic);
        Self::from_mnemonic(&mnemonic, "")
    }

    /// Derives a shared vault secret from a mnemonic and version.
    pub fn derive_keyring_secret(
        phrase: &str,
        passphrase: &str,
        version: u32,
    ) -> Result<GraphKey, AksharaError> {
        let master = MasterIdentity::from_mnemonic(phrase, passphrase)?;
        master.derive_keyring_secret(version)
    }

    pub fn generate_mnemonic() -> Result<String, AksharaError> {
        mnemonic::generate_mnemonic()
    }

    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, AksharaError> {
        Self::from_mnemonic_at_path(phrase, passphrase, "m/44'/999'/0'/0'/0'")
    }

    /// Derives a specific functional branch (0-5) from a mnemonic.
    pub fn derive_branch_from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        branch_index: u32,
    ) -> Result<Self, AksharaError> {
        let path = crate::identity::paths::format_akshara_path(branch_index, 0);
        Self::from_mnemonic_at_path(mnemonic, passphrase, &path)
    }

    pub fn from_mnemonic_at_path(
        phrase: &str,
        passphrase: &str,
        path: &str,
    ) -> Result<Self, AksharaError> {
        let master = MasterIdentity::from_mnemonic(phrase, passphrase)?;
        master.derive_child(path, None)
    }

    /// Serialize the identity to bytes (64 bytes: 32-byte signing key + 32-byte encryption key).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.signing_key.as_bytes());
        bytes.extend_from_slice(self.encryption_key.as_bytes());
        Zeroizing::new(bytes)
    }

    /// Deserialize an identity from bytes (64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AksharaError> {
        if bytes.len() != 64 {
            return Err(AksharaError::Crypto(
                crate::base::error::CryptoError::InvalidKeyFormat(format!(
                    "Invalid identity bytes length: {}",
                    bytes.len()
                )),
            ));
        }

        let mut signing_bytes = [0u8; 32];
        let mut encryption_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(&bytes[0..32]);
        encryption_bytes.copy_from_slice(&bytes[32..64]);

        Ok(Self {
            signing_key: SigningSecretKey::new(signing_bytes),
            encryption_key: EncryptionSecretKey::new(encryption_bytes),
            public: Identity {
                signing_key: SigningPublicKey::new(signing_bytes),
                encryption_key: EncryptionPublicKey::new(encryption_bytes),
            },
            derivation_path: "m/44'/999'/0'/0'/branch".to_string(),
        })
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

    pub fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey, AksharaError> {
        let mut hmac =
            Hmac::<Sha512>::new_from_slice(self.signing_key.as_bytes()).map_err(|e| {
                AksharaError::InternalError(format!("HMAC initialization failed: {}", e))
            })?;

        hmac.update(b"akshara.v1.graph_key");
        hmac.update(graph_id.as_bytes());

        let output = hmac.finalize().into_bytes();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&output[0..32]);

        Ok(GraphKey::new(key_bytes))
    }

    pub fn derive_keyring_secret_key(&self) -> GraphKey {
        GraphKey::new(*self.public().signing_key().as_bytes())
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

    pub fn derivation_path(&self) -> &str {
        &self.derivation_path
    }

    /// Derives a Graph-Isolated Shadow Identity for a specific graph.
    ///
    /// This prevents "Clustering" attacks on the Relay by ensuring the signer's
    /// public key is unique to this specific graph.
    pub fn derive_shadow_identity(&self, graph_id: &GraphId) -> Result<Self, AksharaError> {
        // AKSHARA RITUAL: Use the SECRET key as the HMAC key to ensure the shadow
        // identity is actually a secret that cannot be forged by observers.
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(self.signing_key.as_bytes())
            .map_err(|e| AksharaError::InternalError(format!("HMAC init failed: {}", e)))?;
        hmac.update(b"akshara.v1.shadow_identity");
        hmac.update(graph_id.as_bytes());
        let result = hmac.finalize().into_bytes();
        let mut shadow_seed = [0u8; 32];
        shadow_seed.copy_from_slice(&result[..32]);

        let shadow_signing_key = SigningKey::from_bytes(&shadow_seed);

        // The shadow identity inherits the same derivation path string but is marked as shadowed
        let path = format!("{}#shadow({})", self.derivation_path, graph_id);

        Ok(Self::from_signing_key_at_path(shadow_signing_key, path))
    }

    /// Creates an encrypted Shadow Certificate for a specific graph.
    pub fn create_shadow_certificate(
        &self,
        shadow_public: &SigningPublicKey,
        graph_id: &GraphId,
        graph_key: &GraphKey,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<crate::base::crypto::BlockContent, AksharaError> {
        // 1. Create the signed certificate
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(shadow_public.as_bytes());
        data_to_sign.extend_from_slice(graph_id.as_bytes());

        let certificate = ShadowCertificate {
            master_public_key: self.public.signing_key().clone(),
            signature: self.sign(&data_to_sign),
        };

        // 2. Encrypt it with the GraphKey to hide the master identity from the Relay
        let plaintext = crate::base::encoding::to_canonical_bytes(&certificate)?;
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        // LOCKBOX RITUAL: Bind to the graph_id
        let ad = graph_id.as_bytes();

        crate::base::crypto::BlockContent::encrypt(&plaintext, graph_key, nonce, ad)
    }

    /// Decrypts and verifies a Shadow Certificate.
    pub fn verify_shadow_certificate(
        shadow_public: &SigningPublicKey,
        graph_id: &GraphId,
        graph_key: &GraphKey,
        encrypted_proof: &crate::base::crypto::BlockContent,
    ) -> Result<SigningPublicKey, AksharaError> {
        // 1. Decrypt the certificate
        let ad = graph_id.as_bytes();
        let plaintext = encrypted_proof.decrypt(graph_key, ad)?;
        let certificate: ShadowCertificate =
            crate::base::encoding::from_canonical_bytes(&plaintext)?;

        // 2. Verify the master identity signed this specific shadow for this graph
        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(shadow_public.as_bytes());
        data_to_verify.extend_from_slice(graph_id.as_bytes());

        certificate
            .master_public_key
            .verify(&data_to_verify, &certificate.signature)?;

        Ok(certificate.master_public_key)
    }

    /// Derives an isolated, anonymous Discovery ID (Lakshana) for a specific graph.
    ///
    /// This method is for use by an authorized device (Tier 3) that does not
    /// possess the Master Seed but has its own derived Branch 5 key.
    pub fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana, AksharaError> {
        // AKSHARA RITUAL: For a device, we use its own signing key as the HMAC salt
        // This isolates discovery to the specific device-graph pair.
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(self.public.signing_key().as_bytes())
            .map_err(|e| {
            AksharaError::InternalError(format!("HMAC initialization failed: {}", e))
        })?;

        hmac.update(b"akshara.v1.discovery");
        hmac.update(graph_id.as_bytes());

        let result = hmac.finalize().into_bytes();
        let mut lakshana_bytes = [0u8; 32];
        lakshana_bytes.copy_from_slice(&result[..32]);

        Ok(Lakshana::new(lakshana_bytes))
    }

    /// Derives the root Identity Lakshana from this identity's key.
    pub fn derive_identity_lakshana(&self) -> Result<Lakshana, AksharaError> {
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(self.public.signing_key().as_bytes())
            .map_err(|e| {
            AksharaError::InternalError(format!("HMAC initialization failed: {}", e))
        })?;

        hmac.update(b"akshara.v1.discovery");

        let result = hmac.finalize().into_bytes();
        let mut lakshana_bytes = [0u8; 32];
        lakshana_bytes.copy_from_slice(&result[..32]);

        Ok(Lakshana::new(lakshana_bytes))
    }

    /// Signs a manifest header using a graph-isolated shadow identity.
    ///
    /// This method automatically:
    /// 1. Derives the Shadow Identity for the given graph.
    /// 2. (Optional) Attaches a Shadow Certificate if a GraphKey is provided.
    /// 3. Hashes the signer's derivation path for the manifest header.
    /// 4. Computes the Header CID and returns the (ShadowPub, Signature) pair.
    pub fn sign_manifest_shadowed(
        &self,
        header: &mut crate::graph::ManifestHeader,
        graph_id: &GraphId,
        graph_key: Option<&GraphKey>,
    ) -> Result<(SigningPublicKey, Signature), AksharaError> {
        let shadow = self.derive_shadow_identity(graph_id)?;
        let shadow_pub = shadow.public().signing_key().clone();

        // 1. If a GraphKey is provided, attach a Shadow Certificate
        if let Some(key) = graph_key {
            let mut rng = rand::rngs::OsRng;
            let cert = self.create_shadow_certificate(&shadow_pub, graph_id, key, &mut rng)?;
            header.authority_proof = Some(cert);
        }

        // 2. Update header with the signer's path hash
        let mut path_hasher = sha2::Sha256::new();
        path_hasher.update(shadow.derivation_path().as_bytes());
        header.signer_path_hash = path_hasher.finalize().into();

        // 3. Compute the Header ID and sign it
        let header_id = crate::graph::Manifest::compute_header_id(header, &shadow_pub);
        let signature = shadow.sign(header_id.as_ref());

        Ok((shadow_pub, signature))
    }

    /// Derives the Identity ID from this identity's key.
    pub fn identity_id(&self) -> Result<GraphId, AksharaError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"akshara.v1.identity");
        hasher.update(self.public.signing_key().as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&result[..16]);
        Ok(GraphId::from_bytes(bytes))
    }
}

impl PreKeyBundle {
    /// Verifies the integrity and authority of the bundle.
    pub fn verify(&self) -> Result<(), AksharaError> {
        let mut data_to_verify = crate::base::encoding::to_canonical_bytes(&self.device_identity)?;
        data_to_verify.extend(crate::base::encoding::to_canonical_bytes(&self.pre_keys)?);

        self.device_identity
            .signing_key()
            .verify(&data_to_verify, &self.signature)
    }
}

impl AksharaSigner for SecretIdentity {
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
