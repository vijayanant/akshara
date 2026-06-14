//! Configuration for the Akshara client.

use std::path::PathBuf;

pub use crate::vault::VaultConfig;

/// Configuration for the Akshara client.
#[derive(Default)]
pub struct ClientConfig {
    vault: VaultConfig,
    storage: StorageConfig,
    tuning: TuningConfig,
}

impl ClientConfig {
    /// Create a new default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure platform vault (Keychain on macOS/iOS, Windows Credential Manager).
    pub fn with_platform_vault(mut self) -> Self {
        self.vault = VaultConfig::Platform { passphrase: None };
        self
    }

    /// Configure platform vault with a secure passphrase.
    pub fn with_platform_vault_and_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.vault = VaultConfig::Platform {
            passphrase: Some(passphrase.into()),
        };
        self
    }

    /// Configure ephemeral vault (testing only).
    pub fn with_ephemeral_vault(mut self) -> Self {
        self.vault = VaultConfig::Ephemeral { passphrase: None };
        self
    }

    /// Configure ephemeral vault with a secure passphrase (testing only).
    pub fn with_ephemeral_vault_and_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.vault = VaultConfig::Ephemeral {
            passphrase: Some(passphrase.into()),
        };
        self
    }

    /// Configure SQLite storage at the given path.
    pub fn with_sqlite_storage(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage = StorageConfig::Sqlite { path: path.into() };
        self
    }

    /// Configure in-memory storage (testing only).
    pub fn with_in_memory_storage(mut self) -> Self {
        self.storage = StorageConfig::InMemory;
        self
    }

    /// Configure tuning parameters.
    pub fn with_tuning(mut self, tuning: TuningConfig) -> Self {
        self.tuning = tuning;
        self
    }

    /// Returns the vault configuration.
    pub fn vault(&self) -> &VaultConfig {
        &self.vault
    }

    /// Returns the storage configuration.
    pub fn storage(&self) -> &StorageConfig {
        &self.storage
    }

    /// Returns the tuning configuration.
    pub fn tuning(&self) -> &TuningConfig {
        &self.tuning
    }
}

/// Storage backend configuration.
#[derive(Debug, Clone, Default)]
pub enum StorageConfig {
    /// SQLite-backed persistent store at the given path.
    Sqlite { path: PathBuf },

    /// In-memory store, for testing and ephemeral use.
    #[default]
    InMemory,
}

/// Tuning parameters for performance optimization.
#[derive(Debug, Clone)]
pub struct TuningConfig {
    /// Duration of idle time before auto-flush triggers.
    /// Default: 5 seconds.
    pub auto_flush_timeout: std::time::Duration,

    /// Maximum number of staged operations before auto-flush triggers.
    /// Default: 100.
    pub auto_flush_op_threshold: usize,

    /// Maximum total bytes of staged data before auto-flush triggers.
    /// Default: 10 MB.
    pub auto_flush_size_threshold: usize,

    /// Maximum size of a single block. Payloads exceeding this are
    /// rejected unless the field is annotated with #[chunked].
    /// Default: 1 MB.
    pub max_block_size: usize,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            auto_flush_timeout: std::time::Duration::from_secs(5),
            auto_flush_op_threshold: 100,
            auto_flush_size_threshold: 10 * 1024 * 1024,
            max_block_size: 1024 * 1024,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================


