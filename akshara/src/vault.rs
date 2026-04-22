//! Vault abstraction for secure key management.
//!
//! The Vault is the **security boundary** - it holds branch keys and performs
//! cryptographic operations without ever exposing the master seed.

use std::sync::Arc;
use tokio::sync::Mutex;

use akshara_aadhaara::{
    AksharaSigner, GraphDescriptor, GraphId, GraphKey, IdentityGraph, InMemoryStore, Lakshana,
    ManifestId, SecretIdentity, Signature, paths,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result, VaultError};

/// Vault trait for secure key management.
#[async_trait::async_trait]
pub trait Vault: Send + Sync {
    /// Initialize the vault with a mnemonic or generate a new one.
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String>;

    /// Check if the vault is initialized.
    fn is_initialized(&self) -> bool;

    /// Derives a graph-specific symmetric key (Branch 2 — Secret).
    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey>;

    /// Derives the anonymous Lakshana (Branch 5) for a graph.
    async fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana>;

    /// Derives the Keyring Secret (Branch 4) for cross-device sync.
    async fn derive_keyring_secret(&self, version: u32) -> Result<GraphKey>;

    /// Gets the user's own Identity Graph identifier.
    async fn get_identity_id(&self) -> Result<GraphId>;

    /// Gets the user's own Identity Graph discovery identifier.
    async fn get_identity_lakshana(&self) -> Result<Lakshana>;

    /// Discovers resources by walking the Identity Graph.
    async fn list_resources(
        &self,
        store: &InMemoryStore,
    ) -> Result<Vec<(akshara_aadhaara::Address, GraphDescriptor)>>;

    /// Sign data with the identity's signing key.
    async fn sign(&self, graph_id: &GraphId, data: &[u8]) -> Result<Signature>;

    /// Get a fresh identity for verification purposes.
    async fn get_identity(&self, graph_id: Option<&GraphId>) -> Result<SecretIdentity>;

    /// Get the latest known identity anchor CID.
    fn latest_identity_anchor(&self) -> ManifestId;

    /// Update the latest known identity anchor CID.
    fn update_identity_anchor(&self, anchor: ManifestId);

    /// Clear sensitive data from memory.
    fn clear(&self);
}

/// Vault configuration.
#[derive(Default)]
pub enum VaultConfig {
    /// macOS Keychain or iOS Secure Enclave
    #[default]
    Platform,
    /// In-memory vault (testing only - NOT SECURE)
    Ephemeral,
    /// Custom vault implementation
    Custom { backend: Arc<dyn Vault> },
}

impl Clone for VaultConfig {
    fn clone(&self) -> Self {
        match self {
            Self::Platform => Self::Platform,
            Self::Ephemeral => Self::Ephemeral,
            Self::Custom { backend } => Self::Custom {
                backend: backend.clone(),
            },
        }
    }
}

/// Factory function to create a vault based on configuration.
pub fn create_vault(config: VaultConfig) -> Result<Arc<dyn Vault>> {
    match config {
        VaultConfig::Platform => Ok(Arc::new(PlatformVault::new("akshara".to_string()))),
        VaultConfig::Ephemeral => Ok(Arc::new(EphemeralVault::new())),
        VaultConfig::Custom { backend } => Ok(backend),
    }
}

// ============================================================================
// Platform Vault (Keychain / Secure Enclave)
// ============================================================================

/// Vault implementation using platform-native secure storage.
pub struct PlatformVault {
    service: String,
    anchor: Mutex<ManifestId>,
}

impl PlatformVault {
    pub fn new(service: String) -> Self {
        Self {
            service,
            anchor: Mutex::new(ManifestId::null()),
        }
    }

    fn branch_key(index: u32) -> String {
        format!("branch:{}", index)
    }

    fn save_branch(&self, index: u32, data: &[u8]) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, &Self::branch_key(index))
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        let password = hex::encode(data);
        entry
            .set_password(&password)
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;
        Ok(())
    }

    fn load_branch(&self, index: u32) -> Result<Vec<u8>> {
        let entry = keyring::Entry::new(&self.service, &Self::branch_key(index))
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        let password = entry
            .get_password()
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        hex::decode(password)
            .map_err(|e| Error::Vault(VaultError::Keychain(format!("Hex decode failed: {}", e))))
    }
}

#[async_trait::async_trait]
impl Vault for PlatformVault {
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String> {
        if self.load_branch(0).is_ok() {
            return Ok("existing".to_string());
        }

        let mnemonic = match mnemonic {
            Some(m) => Zeroizing::new(m),
            None => Zeroizing::new(SecretIdentity::generate_mnemonic().map_err(|e| {
                Error::Vault(VaultError::Keychain(format!(
                    "Failed to generate mnemonic: {}",
                    e
                )))
            })?),
        };

        for i in 0..=5 {
            let branch = SecretIdentity::derive_branch_from_mnemonic(&mnemonic, "", i)
                .map_err(Error::Protocol)?;
            self.save_branch(i, &branch.to_bytes())?;
        }

        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.load_branch(0).is_ok()
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        let branch2_bytes = self.load_branch(paths::BRANCH_SECRET)?;
        let branch2 = SecretIdentity::from_bytes(&branch2_bytes).map_err(Error::Protocol)?;
        branch2.derive_graph_key(graph_id).map_err(Error::Protocol)
    }

    async fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana> {
        let branch5_bytes = self.load_branch(paths::BRANCH_DISCOVERY)?;
        let branch5 = SecretIdentity::from_bytes(&branch5_bytes).map_err(Error::Protocol)?;
        branch5
            .derive_discovery_id(graph_id)
            .map_err(Error::Protocol)
    }

    async fn derive_keyring_secret(&self, _version: u32) -> Result<GraphKey> {
        Err(Error::Vault(VaultError::DerivationFailed(
            "Keyring derivation in PlatformVault requires Master Seed".to_string(),
        )))
    }

    async fn get_identity_id(&self) -> Result<GraphId> {
        let branch0_bytes = self.load_branch(paths::BRANCH_LEGISLATOR)?;
        let branch0 = SecretIdentity::from_bytes(&branch0_bytes).map_err(Error::Protocol)?;
        branch0.identity_id().map_err(Error::Protocol)
    }

    async fn get_identity_lakshana(&self) -> Result<Lakshana> {
        let branch0_bytes = self.load_branch(paths::BRANCH_LEGISLATOR)?;
        let branch0 = SecretIdentity::from_bytes(&branch0_bytes).map_err(Error::Protocol)?;
        branch0.derive_identity_lakshana().map_err(Error::Protocol)
    }

    async fn list_resources(
        &self,
        store: &InMemoryStore,
    ) -> Result<Vec<(akshara_aadhaara::Address, GraphDescriptor)>> {
        let anchor = self.latest_identity_anchor();
        if anchor == ManifestId::null() {
            return Ok(vec![]);
        }
        let identity_graph = IdentityGraph::new(store);
        identity_graph
            .list_resources(&anchor)
            .await
            .map_err(Error::Protocol)
    }

    async fn sign(&self, graph_id: &GraphId, data: &[u8]) -> Result<Signature> {
        let identity = self.get_identity(Some(graph_id)).await?;
        Ok(identity.sign(data))
    }

    async fn get_identity(&self, graph_id: Option<&GraphId>) -> Result<SecretIdentity> {
        let branch_index = if graph_id.is_some() {
            paths::BRANCH_EXECUTIVE
        } else {
            paths::BRANCH_LEGISLATOR
        };

        let branch_bytes = self.load_branch(branch_index)?;
        let identity = SecretIdentity::from_bytes(&branch_bytes).map_err(Error::Protocol)?;

        if let Some(gid) = graph_id {
            identity
                .derive_shadow_identity(gid)
                .map_err(Error::Protocol)
        } else {
            Ok(identity)
        }
    }

    fn latest_identity_anchor(&self) -> ManifestId {
        match self.anchor.try_lock() {
            Ok(anchor) => *anchor,
            Err(_) => ManifestId::null(),
        }
    }

    fn update_identity_anchor(&self, anchor: ManifestId) {
        if let Ok(mut stored) = self.anchor.try_lock() {
            *stored = anchor;
        }
    }

    fn clear(&self) {}
}

// ============================================================================
// Ephemeral Vault (Testing Only)
// ============================================================================

pub struct EphemeralVault {
    mnemonic: Mutex<Option<Zeroizing<String>>>,
    anchor: Mutex<ManifestId>,
}

impl EphemeralVault {
    pub fn new() -> Self {
        Self {
            mnemonic: Mutex::new(None),
            anchor: Mutex::new(ManifestId::null()),
        }
    }
}

impl Default for EphemeralVault {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Vault for EphemeralVault {
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String> {
        let mut stored = self.mnemonic.lock().await;
        if stored.is_some() {
            return Ok("existing".to_string());
        }

        let mnemonic = mnemonic.unwrap_or_else(|| {
            SecretIdentity::generate_mnemonic().expect("Failed to generate mnemonic")
        });

        *stored = Some(Zeroizing::new(mnemonic));
        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.mnemonic
            .try_lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        let identity = self.get_identity(None).await?;
        identity.derive_graph_key(graph_id).map_err(Error::Protocol)
    }

    async fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, "")
            .map_err(Error::Protocol)?;
        master
            .derive_discovery_id(graph_id)
            .map_err(Error::Protocol)
    }

    async fn derive_keyring_secret(&self, version: u32) -> Result<GraphKey> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, "")
            .map_err(Error::Protocol)?;
        master
            .derive_keyring_secret(version)
            .map_err(Error::Protocol)
    }

    async fn get_identity_id(&self) -> Result<GraphId> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, "")
            .map_err(Error::Protocol)?;
        master.identity_id().map_err(Error::Protocol)
    }

    async fn get_identity_lakshana(&self) -> Result<Lakshana> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, "")
            .map_err(Error::Protocol)?;
        master.derive_identity_lakshana().map_err(Error::Protocol)
    }

    async fn list_resources(
        &self,
        store: &InMemoryStore,
    ) -> Result<Vec<(akshara_aadhaara::Address, GraphDescriptor)>> {
        let anchor = self.latest_identity_anchor();
        if anchor == ManifestId::null() {
            return Ok(vec![]);
        }
        let identity_graph = IdentityGraph::new(store);
        identity_graph
            .list_resources(&anchor)
            .await
            .map_err(Error::Protocol)
    }

    async fn sign(&self, graph_id: &GraphId, data: &[u8]) -> Result<Signature> {
        let identity = self.get_identity(Some(graph_id)).await?;
        Ok(identity.sign(data))
    }

    async fn get_identity(&self, graph_id: Option<&GraphId>) -> Result<SecretIdentity> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;

        if let Some(gid) = graph_id {
            let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, "")
                .map_err(Error::Protocol)?;
            master
                .derive_child("m/44'/999'/0'/1'/0'", Some(gid))
                .map_err(Error::Protocol)
        } else {
            SecretIdentity::from_mnemonic(mnemonic, "").map_err(|e| {
                Error::Vault(VaultError::KeyNotFound(format!(
                    "Identity derivation failed: {}",
                    e
                )))
            })
        }
    }

    fn latest_identity_anchor(&self) -> ManifestId {
        match self.anchor.try_lock() {
            Ok(anchor) => *anchor,
            Err(_) => ManifestId::null(),
        }
    }

    fn update_identity_anchor(&self, anchor: ManifestId) {
        if let Ok(mut stored) = self.anchor.try_lock() {
            *stored = anchor;
        }
    }

    fn clear(&self) {
        if let Ok(mut stored) = self.mnemonic.try_lock() {
            *stored = None;
        }
    }
}

impl Drop for EphemeralVault {
    fn drop(&mut self) {
        // Zeroize on drop handled via Mutex<Option<Zeroizing<String>>>
    }
}
