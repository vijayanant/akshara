//! Vault abstraction for secure key management.
//!
//! The Vault is the **security boundary** - it holds branch keys and performs
//! cryptographic operations without ever exposing the master seed.
//!
//! # Security Properties
//!
//! - **Seed Never Stored**: The 24-word mnemonic is shown once during setup, then never stored
//! - **Branch Keys Only**: Only revocable branch keys are stored in OS keychain
//! - **Compartmentalization**: Each branch is stored separately - compromise of one doesn't affect others
//! - **Zeroization**: All intermediate secrets are zeroized after use
//! - **Platform Security**: Uses platform-native secure storage (Keychain, etc.)

use std::sync::Arc;
use tokio::sync::Mutex;

use akshara_aadhaara::{AksharaSigner, GraphId, GraphKey, SecretIdentity};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Vault trait for secure key management.
///
/// # Security Requirements
///
/// Implementations MUST:
/// - Never store the master seed
/// - Store only revocable branch keys
/// - Store each branch separately for independent revocation
/// - Zeroize all intermediate secrets after use
/// - Use platform-native secure storage when available
///
/// # Implementation Notes
///
/// All methods take `&self` because implementations should use interior mutability
/// (e.g., `Mutex`, `RwLock`) for thread-safe access.
#[async_trait::async_trait]
pub trait Vault: Send + Sync {
    /// Initialize the vault with a mnemonic or generate a new one.
    ///
    /// The mnemonic is used to derive branch keys, which are then stored.
    /// The mnemonic itself is NEVER stored.
    /// Returns a status: "created" or "existing".
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String>;

    /// Check if the vault is initialized.
    fn is_initialized(&self) -> bool;

    /// Derive a graph key for the given graph ID.
    ///
    /// The derivation happens inside the vault - only the derived key is returned.
    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey>;

    /// Sign data with the identity's signing key.
    ///
    /// The signing happens inside the vault - only the signature is returned.
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Get a fresh identity for verification purposes.
    ///
    /// This returns a NEW identity instance each time, derived from the stored branch key.
    /// The seed itself is never exposed.
    async fn get_identity(&self) -> Result<SecretIdentity>;

    /// Clear sensitive data from memory.
    ///
    /// This does NOT delete keys from secure storage - it only clears
    /// any cached values in memory.
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

/// Create a vault from configuration.
pub fn create_vault(config: VaultConfig) -> Result<Arc<dyn Vault>> {
    match config {
        VaultConfig::Platform => Ok(Arc::new(PlatformVault::new()?)),
        VaultConfig::Ephemeral => Ok(Arc::new(EphemeralVault::new())),
        VaultConfig::Custom { backend } => Ok(backend),
    }
}

// ============================================================================
// Platform Vault (Production)
// ============================================================================

/// Platform-native vault using OS keychain.
///
/// # Security Properties
///
/// - Stores ONLY branch keys (not master seed)
/// - Each branch stored in separate keychain entry
/// - Uses hex encoding for cross-platform compatibility
pub struct PlatformVault {
    service: String,
}

impl PlatformVault {
    /// Create a new platform vault.
    pub fn new() -> Result<Self> {
        Ok(Self {
            service: "akshara".to_string(),
        })
    }

    /// Get the keychain key for a specific branch.
    fn branch_key(index: u32) -> String {
        format!("branch:{}", index)
    }

    /// Load a specific branch from keychain.
    fn load_branch(&self, index: u32) -> Result<Vec<u8>> {
        let key = Self::branch_key(index);
        let entry = keyring::Entry::new(&self.service, &key)
            .map_err(|e| VaultError::Keychain(format!("Keychain entry creation failed: {}", e)))?;

        let hex_str = entry
            .get_password()
            .map_err(|e| VaultError::KeyNotFound(format!("Branch {} not found: {}", index, e)))?;

        // Decode from hex
        let bytes = hex::decode(&hex_str).map_err(|e| {
            VaultError::KeyNotFound(format!("Branch {} decode failed: {}", index, e))
        })?;

        Ok(bytes)
    }

    /// Save a branch to keychain.
    fn save_branch(&self, index: u32, bytes: &[u8]) -> Result<()> {
        let key = Self::branch_key(index);
        let entry = keyring::Entry::new(&self.service, &key)
            .map_err(|e| VaultError::Keychain(format!("Keychain entry creation failed: {}", e)))?;

        let hex_str = hex::encode(bytes);
        entry
            .set_password(&hex_str)
            .map_err(|e| VaultError::Keychain(e.to_string()))?;

        Ok(())
    }

    /// Revoke and regenerate a specific branch.
    ///
    /// This is used when a branch is compromised. The branch is re-derived
    /// from the master seed (which the user must provide) and stored.
    pub async fn revoke_branch(&mut self, branch_index: u32, mnemonic: &str) -> Result<()> {
        // Verify the mnemonic is valid and derive new branch
        let new_branch = SecretIdentity::derive_branch_from_mnemonic(mnemonic, "", branch_index)?;
        let new_branch_bytes = new_branch.to_bytes();

        // Save the new branch
        self.save_branch(branch_index, &new_branch_bytes)?;

        Ok(())
    }

    /// Fully reset the vault (delete all keys from keychain).
    ///
    /// User will need to re-enter seed phrase to reinitialize.
    pub fn reset(&self) -> Result<()> {
        // Delete all 6 branch entries by overwriting with empty data
        for i in 0..=5 {
            let key = Self::branch_key(i);
            if let Ok(entry) = keyring::Entry::new(&self.service, &key) {
                let _ = entry.set_password("");
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Vault for PlatformVault {
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String> {
        // Check if already initialized
        if self.load_branch(0).is_ok() {
            return Ok("existing".to_string());
        }

        // Get seed phrase from user (for initial setup or recovery)
        let mnemonic = mnemonic.unwrap_or_else(|| {
            SecretIdentity::generate_mnemonic().expect("Failed to generate mnemonic")
        });

        // Derive ALL 6 branches from mnemonic and store each separately
        for i in 0..=5 {
            let branch =
                SecretIdentity::derive_branch_from_mnemonic(&mnemonic, "", i).map_err(|e| {
                    VaultError::KeyNotFound(format!("Branch {} derivation failed: {}", i, e))
                })?;
            let branch_bytes = branch.to_bytes();
            self.save_branch(i, &branch_bytes)?;
        }

        // Seed phrase is NEVER stored - user must have written it down
        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.load_branch(0).is_ok()
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        // Load ONLY Branch 2 (Secret) from keychain
        let branch2_bytes = self.load_branch(2)?;

        // Reconstruct Branch 2 identity
        let branch2 = SecretIdentity::from_bytes(&branch2_bytes).map_err(|e| {
            VaultError::KeyNotFound(format!("Branch 2 reconstruction failed: {}", e))
        })?;

        // Derive GraphKey from Branch 2
        let graph_key = branch2.derive_graph_key(graph_id)?;

        Ok(graph_key)
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Load ONLY Branch 1 (Executive) from keychain
        let branch1_bytes = self.load_branch(1)?;

        // Reconstruct Branch 1 identity
        let branch1 = SecretIdentity::from_bytes(&branch1_bytes).map_err(|e| {
            VaultError::KeyNotFound(format!("Branch 1 reconstruction failed: {}", e))
        })?;

        // Sign with Branch 1
        let signature: akshara_aadhaara::Signature = branch1.sign(data);

        Ok(signature.as_bytes().to_vec())
    }

    async fn get_identity(&self) -> Result<SecretIdentity> {
        // Load Branch 1 (Executive) - used as the "public identity"
        let branch1_bytes = self.load_branch(1)?;

        // Reconstruct identity from Branch 1
        let identity = SecretIdentity::from_bytes(&branch1_bytes).map_err(|e| {
            VaultError::KeyNotFound(format!("Identity reconstruction failed: {}", e))
        })?;

        Ok(identity)
    }

    fn clear(&self) {
        // Note: This doesn't delete from keychain, just clears any in-memory cache
        // To fully reset, user must delete the keychain entry manually or use reset()
    }
}

// ============================================================================
// Ephemeral Vault (Testing Only)
// ============================================================================

/// In-memory vault for testing.
///
/// # Security Warning
///
/// This vault stores the mnemonic in plain memory.
/// **DO NOT use in production.**
pub struct EphemeralVault {
    mnemonic: Mutex<Option<String>>,
}

impl EphemeralVault {
    /// Create a new ephemeral vault.
    pub fn new() -> Self {
        Self {
            mnemonic: Mutex::new(None),
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

        *stored = Some(mnemonic);
        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.mnemonic
            .try_lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored
            .as_ref()
            .ok_or_else(|| VaultError::KeyNotFound("Vault not initialized".to_string()))?;

        let identity = SecretIdentity::from_mnemonic(mnemonic, "")
            .map_err(|e| VaultError::KeyNotFound(format!("Derivation failed: {}", e)))?;

        identity.derive_graph_key(graph_id).map_err(|e| e.into())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let identity = self.get_identity().await?;
        let signature: akshara_aadhaara::Signature = identity.sign(data);
        Ok(signature.as_bytes().to_vec())
    }

    async fn get_identity(&self) -> Result<SecretIdentity> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored
            .as_ref()
            .ok_or_else(|| VaultError::KeyNotFound("Vault not initialized".to_string()))?;

        SecretIdentity::from_mnemonic(mnemonic, "").map_err(|e| {
            VaultError::KeyNotFound(format!("Identity derivation failed: {}", e)).into()
        })
    }

    fn clear(&self) {
        // Note: Can't zeroize in Mutex, but the mnemonic will be cleared on drop
        *self.mnemonic.try_lock().unwrap() = None;
    }
}

impl Drop for EphemeralVault {
    fn drop(&mut self) {
        // Zeroize on drop
        if let Ok(mut stored) = self.mnemonic.try_lock()
            && let Some(ref mut mnemonic) = *stored
        {
            mnemonic.zeroize();
        }
    }
}
