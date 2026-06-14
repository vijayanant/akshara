//! Vault abstraction for secure key management.
//!
//! The Vault is the **security boundary** - it holds branch keys and performs
//! cryptographic operations without ever exposing the master seed.

pub mod ephemeral;
pub mod platform;

pub use ephemeral::EphemeralVault;
pub use platform::PlatformVault;

use std::sync::Arc;

use akshara_aadhaara::{
    GraphDescriptor, GraphId, GraphKey, Lakshana, ManifestId, SecretIdentity, Signature,
};

use crate::error::Result;

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
        store: &(dyn akshara_aadhaara::GraphStore + Send + Sync),
    ) -> Result<Vec<(akshara_aadhaara::Address, GraphDescriptor)>>;

    /// Sign data with the identity's signing key.
    async fn sign(&self, graph_id: &GraphId, data: &[u8]) -> Result<Signature>;

    /// Get a fresh identity for verification purposes.
    async fn get_identity(&self, graph_id: Option<&GraphId>) -> Result<SecretIdentity>;

    /// Gets the unshadowed Executive identity.
    async fn get_executive_identity(&self) -> Result<SecretIdentity>;

    /// Get the latest known identity anchor CID.
    fn latest_identity_anchor(&self) -> ManifestId;

    /// Update the latest known identity anchor CID.
    fn update_identity_anchor(&self, anchor: ManifestId);

    /// Clear sensitive data from memory.
    fn clear(&self);
}

/// Vault configuration.
pub enum VaultConfig {
    /// macOS Keychain or iOS Secure Enclave
    Platform { passphrase: Option<String> },
    /// In-memory vault (testing only - NOT SECURE)
    Ephemeral { passphrase: Option<String> },
    /// Custom vault implementation
    Custom { backend: Arc<dyn Vault> },
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::Platform { passphrase: None }
    }
}

impl Clone for VaultConfig {
    fn clone(&self) -> Self {
        match self {
            Self::Platform { passphrase } => Self::Platform {
                passphrase: passphrase.clone(),
            },
            Self::Ephemeral { passphrase } => Self::Ephemeral {
                passphrase: passphrase.clone(),
            },
            Self::Custom { backend } => Self::Custom {
                backend: backend.clone(),
            },
        }
    }
}

/// Factory function to create a vault based on configuration.
pub fn create_vault(config: VaultConfig) -> Result<Arc<dyn Vault>> {
    match config {
        VaultConfig::Platform { passphrase } => Ok(Arc::new(PlatformVault::new(
            "akshara".to_string(),
            passphrase,
        ))),
        VaultConfig::Ephemeral { passphrase } => Ok(Arc::new(EphemeralVault::new(passphrase))),
        VaultConfig::Custom { backend } => Ok(backend),
    }
}
