//! Configuration for the Akshara client.

use crate::vault::VaultConfig;

/// Configuration for the Akshara client.
#[derive(Default)]
pub struct ClientConfig {
    /// Vault configuration
    pub vault: VaultConfig,
    /// Tuning parameters
    pub tuning: TuningConfig,
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

    /// Configure tuning parameters.
    pub fn with_tuning(mut self, tuning: TuningConfig) -> Self {
        self.tuning = tuning;
        self
    }
}

/// Tuning parameters for performance optimization.
#[derive(Debug, Clone)]
pub struct TuningConfig {
    /// Time of inactivity before auto-seal (default: 5 seconds)
    pub seal_idle_timeout: std::time::Duration,
    /// Number of pending operations before auto-seal (default: 100)
    pub seal_op_threshold: usize,
    /// Total size of pending operations before auto-seal (default: 10MB)
    pub seal_size_threshold: usize,
    /// Maximum block size before chunking (default: 1MB)
    pub max_block_size: usize,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            seal_idle_timeout: std::time::Duration::from_secs(5),
            seal_op_threshold: 100,
            seal_size_threshold: 10 * 1024 * 1024,
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
        assert_eq!(config.seal_idle_timeout, std::time::Duration::from_secs(5));
        assert_eq!(config.seal_op_threshold, 100);
        assert_eq!(config.seal_size_threshold, 10 * 1024 * 1024);
        assert_eq!(config.max_block_size, 1024 * 1024);
    }

    #[test]
    fn tuning_config_clone() {
        let config = TuningConfig::default();
        let cloned = config.clone();
        assert_eq!(config.seal_idle_timeout, cloned.seal_idle_timeout);
        assert_eq!(config.seal_op_threshold, cloned.seal_op_threshold);
    }

    #[test]
    fn tuning_config_zero_timeout() {
        let config = TuningConfig {
            seal_idle_timeout: std::time::Duration::from_secs(0),
            ..TuningConfig::default()
        };
        assert_eq!(config.seal_idle_timeout, std::time::Duration::from_secs(0));
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
    fn client_config_with_tuning() {
        let tuning = TuningConfig {
            seal_idle_timeout: std::time::Duration::from_secs(10),
            seal_op_threshold: 50,
            ..TuningConfig::default()
        };
        let config = ClientConfig::new().with_tuning(tuning.clone());
        assert_eq!(
            config.tuning.seal_idle_timeout,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(config.tuning.seal_op_threshold, 50);
    }

    #[test]
    fn client_config_builder_pattern() {
        let config = ClientConfig::new()
            .with_platform_vault()
            .with_tuning(TuningConfig::default());
        assert!(matches!(config.vault, VaultConfig::Platform));
    }

    #[test]
    fn client_config_multiple_vault_switches() {
        let config = ClientConfig::new()
            .with_ephemeral_vault()
            .with_platform_vault()
            .with_ephemeral_vault();
        assert!(matches!(config.vault, VaultConfig::Ephemeral));
    }

    #[test]
    fn client_config_multiple_tuning_overwrites() {
        let config = ClientConfig::new()
            .with_tuning(TuningConfig {
                seal_op_threshold: 50,
                ..TuningConfig::default()
            })
            .with_tuning(TuningConfig {
                seal_op_threshold: 100,
                ..TuningConfig::default()
            });
        assert_eq!(config.tuning.seal_op_threshold, 100);
    }
}
