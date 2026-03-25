use thiserror::Error;

/// Error types for the Akshara API.
#[derive(Debug, Error)]
pub enum Error {
    // === Identity ===
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),

    // === Storage ===
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Graph not found: {0}")]
    GraphNotFound(String),

    // === Path Resolution ===
    #[error("Path not found: {0}")]
    PathNotFound(String),

    #[error("Cycle detected in index tree")]
    CycleDetected,

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    // === Staging ===
    #[error("Staging store empty, nothing to seal")]
    NothingToSeal,

    #[error("Staging error: {0}")]
    Staging(String),

    // === Sealing ===
    #[error("Chunking failed: {0}")]
    ChunkingFailed(String),

    #[error("Index build failed: {0}")]
    IndexBuildFailed(String),

    // === Sync ===
    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Conflict detected at path {0}")]
    ConflictDetected(String),

    // === Protocol (wrapped from aadhaara) ===
    #[error("Protocol error: {0}")]
    Protocol(#[from] akshara_aadhaara::AksharaError),

    // === Internal ===
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Vault-specific errors.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Keychain error: {0}")]
    Keychain(String),

    #[error("Secure enclave error: {0}")]
    SecureEnclave(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Vault already initialized")]
    AlreadyInitialized,
}

/// Storage-specific errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Database not initialized")]
    DatabaseNotInitialized,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Migration error: {0}")]
    Migration(String),
}

/// Result type alias for Akshara operations.
pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_mnemonic() {
        let err = Error::InvalidMnemonic("invalid words".to_string());
        assert!(err.to_string().contains("invalid words"));
    }

    #[test]
    fn error_display_path_not_found() {
        let err = Error::PathNotFound("/missing/path".to_string());
        assert!(err.to_string().contains("/missing/path"));
    }

    #[test]
    fn error_display_graph_not_found() {
        let err = Error::GraphNotFound("graph-id-123".to_string());
        assert!(err.to_string().contains("graph-id-123"));
    }

    #[test]
    fn error_display_nothing_to_seal() {
        let err = Error::NothingToSeal;
        assert!(err.to_string().to_lowercase().contains("seal"));
    }

    #[test]
    fn error_from_vault_error() {
        let vault_err = VaultError::KeyNotFound("test".to_string());
        let err: Error = vault_err.into();
        assert!(matches!(err, Error::Vault(_)));
    }

    #[test]
    fn error_from_storage_error() {
        let storage_err = StorageError::DatabaseNotInitialized;
        let err: Error = storage_err.into();
        assert!(matches!(err, Error::Storage(_)));
    }

    #[test]
    fn vault_error_keychain() {
        let err = VaultError::Keychain("keychain error".to_string());
        assert!(err.to_string().contains("keychain error"));
    }

    #[test]
    fn vault_error_key_not_found() {
        let err = VaultError::KeyNotFound("missing key".to_string());
        assert!(err.to_string().contains("missing key"));
    }

    #[test]
    fn vault_error_authentication_required() {
        let err = VaultError::AuthenticationRequired;
        assert!(err.to_string().contains("Authentication required"));
    }

    #[test]
    fn storage_error_database_not_initialized() {
        let err = StorageError::DatabaseNotInitialized;
        assert!(err.to_string().contains("Database not initialized"));
    }

    #[test]
    fn storage_error_migration() {
        let err = StorageError::Migration("migration failed".to_string());
        assert!(err.to_string().contains("migration failed"));
    }

    #[test]
    fn error_chain_vault_to_error() {
        let vault_err = VaultError::KeyNotFound("original error".to_string());
        let err = Error::Vault(vault_err);
        let err_str = err.to_string();
        assert!(err_str.contains("Vault error"));
        assert!(err_str.contains("original error"));
    }

    #[test]
    fn error_chain_storage_to_error() {
        let storage_err = StorageError::Migration("original error".to_string());
        let err = Error::Storage(storage_err);
        let err_str = err.to_string();
        assert!(err_str.contains("Storage error"));
        assert!(err_str.contains("original error"));
    }
}
