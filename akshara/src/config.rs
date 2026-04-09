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
        self.vault = VaultConfig::Platform;
        self
    }

    /// Configure ephemeral vault (testing only).
    pub fn with_ephemeral_vault(mut self) -> Self {
        self.vault = VaultConfig::Ephemeral;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuning_config_default() {
        let config = TuningConfig::default();
        assert_eq!(config.auto_flush_timeout, std::time::Duration::from_secs(5));
        assert_eq!(config.auto_flush_op_threshold, 100);
        assert_eq!(config.auto_flush_size_threshold, 10 * 1024 * 1024);
        assert_eq!(config.max_block_size, 1024 * 1024);
    }

    #[test]
    fn tuning_config_clone() {
        let config = TuningConfig::default();
        let cloned = config.clone();
        assert_eq!(config.auto_flush_timeout, cloned.auto_flush_timeout);
        assert_eq!(
            config.auto_flush_op_threshold,
            cloned.auto_flush_op_threshold
        );
    }

    #[test]
    fn tuning_config_zero_timeout() {
        let config = TuningConfig {
            auto_flush_timeout: std::time::Duration::from_secs(0),
            ..TuningConfig::default()
        };
        assert_eq!(config.auto_flush_timeout, std::time::Duration::from_secs(0));
    }

    #[test]
    fn tuning_config_large_block_size() {
        let config = TuningConfig {
            max_block_size: 100 * 1024 * 1024,
            ..TuningConfig::default()
        };
        assert_eq!(config.max_block_size, 100 * 1024 * 1024);
    }

    #[test]
    fn client_config_default() {
        let config = ClientConfig::default();
        assert!(matches!(config.vault, VaultConfig::Platform));
        assert!(matches!(config.storage, StorageConfig::InMemory));
    }

    #[test]
    fn client_config_new() {
        let config = ClientConfig::new();
        assert!(matches!(config.vault, VaultConfig::Platform));
    }

    #[test]
    fn client_config_with_platform_vault() {
        let config = ClientConfig::new().with_platform_vault();
        assert!(matches!(config.vault, VaultConfig::Platform));
    }

    #[test]
    fn client_config_with_ephemeral_vault() {
        let config = ClientConfig::new().with_ephemeral_vault();
        assert!(matches!(config.vault, VaultConfig::Ephemeral));
    }

    #[test]
    fn client_config_with_sqlite_storage() {
        let config = ClientConfig::new().with_sqlite_storage("/tmp/test.db");
        assert!(matches!(config.storage, StorageConfig::Sqlite { .. }));
    }

    #[test]
    fn client_config_with_in_memory_storage() {
        let config = ClientConfig::new().with_in_memory_storage();
        assert!(matches!(config.storage, StorageConfig::InMemory));
    }

    #[test]
    fn client_config_with_tuning() {
        let tuning = TuningConfig {
            auto_flush_timeout: std::time::Duration::from_secs(10),
            auto_flush_op_threshold: 50,
            ..TuningConfig::default()
        };
        let config = ClientConfig::new().with_tuning(tuning.clone());
        assert_eq!(
            config.tuning.auto_flush_timeout,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(config.tuning.auto_flush_op_threshold, 50);
    }

    #[test]
    fn client_config_builder_pattern() {
        let config = ClientConfig::new()
            .with_platform_vault()
            .with_in_memory_storage()
            .with_tuning(TuningConfig::default());
        assert!(matches!(config.vault, VaultConfig::Platform));
        assert!(matches!(config.storage, StorageConfig::InMemory));
    }

    #[test]
    fn client_config_accessors() {
        let config = ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage();
        assert!(matches!(config.vault(), VaultConfig::Ephemeral));
        assert!(matches!(config.storage(), StorageConfig::InMemory));
        assert_eq!(config.tuning().max_block_size, 1024 * 1024);
    }

    #[test]
    fn storage_config_clone() {
        let storage = StorageConfig::Sqlite {
            path: PathBuf::from("/tmp/test.db"),
        };
        let cloned = storage.clone();
        assert!(matches!(cloned, StorageConfig::Sqlite { .. }));
    }
}
