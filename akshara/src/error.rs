use thiserror::Error;

use akshara_aadhaara::GraphId;

/// Error types for the Akshara API.
#[derive(Debug, Error)]
pub enum Error {
    // === Identity & Vault (category: IDENTITY) ===
    #[error("vault initialization failed: {0}")]
    VaultInit(String),

    #[error("invalid mnemonic: {reason}")]
    InvalidMnemonic { reason: String },

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("identity error: {0}")]
    Identity(String),

    // === Storage (category: STORAGE) ===
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    // === Graph Operations (category: GRAPH) ===
    #[error("graph not found: {0}")]
    GraphNotFound(GraphId),

    #[error("invalid lakshana: {0}")]
    InvalidLakshana(String),

    #[error("nothing to flush — staging is empty")]
    NothingToFlush,

    #[error("invalid path: {path} — {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("path not found: {0}")]
    PathNotFound(String),

    // === Serialization (category: SERDE) ===
    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("deserialization failed: {path}: {reason}")]
    Deserialization { path: String, reason: String },

    // === Crypto (category: CRYPTO) ===
    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("block size exceeded: path={path}, size={size}, max={max}")]
    BlockSizeExceeded {
        path: String,
        size: usize,
        max: usize,
    },

    // === Sync (category: SYNC) ===
    #[error("sync failed: {0}")]
    SyncFailed(String),

    #[error("sync transport error: {0}")]
    SyncTransport(String),

    // === Access Control (category: ACCESS) ===
    #[error("access denied: {resource} — {reason}")]
    AccessDenied { resource: String, reason: String },

    #[error("revoked grant: {0}")]
    RevokedGrant(String),

    #[error("transfer failed: {0}")]
    TransferFailed(String),

    // === Conflicts (category: CONFLICT) ===
    #[error("conflict detected at path: {0}")]
    Conflict(String),

    #[error("conflict resolution failed: {0}")]
    ConflictResolution(String),

    // === Audit (category: AUDIT) ===
    #[error("authority verification failed: {0}")]
    AuthorityVerificationFailed(String),

    #[error("provenance incomplete: {0}")]
    ProvenanceIncomplete(String),

    // === Internal (category: INTERNAL) ===
    #[error("internal error: {0}")]
    Internal(String),

    // === Protocol (wrapped from aadhaara) ===
    #[error("protocol error: {0}")]
    Protocol(#[from] akshara_aadhaara::AksharaError),
}

/// Vault-specific errors.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("secure enclave error: {0}")]
    SecureEnclave(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("authentication required")]
    AuthenticationRequired,

    #[error("vault already initialized")]
    AlreadyInitialized,
}

/// Storage-specific errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("database not initialized")]
    DatabaseNotInitialized,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("migration error: {0}")]
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
        let err = Error::InvalidMnemonic {
            reason: "invalid words".to_string(),
        };
        assert!(err.to_string().contains("invalid words"));
    }

    #[test]
    fn error_display_path_not_found() {
        let err = Error::PathNotFound("/missing/path".to_string());
        assert!(err.to_string().contains("/missing/path"));
    }

    #[test]
    fn error_display_graph_not_found() {
        let graph_id = GraphId::new();
        let err = Error::GraphNotFound(graph_id);
        let s = err.to_string();
        assert!(s.contains("graph not found"));
    }

    #[test]
    fn error_display_nothing_to_flush() {
        let err = Error::NothingToFlush;
        assert!(err.to_string().contains("flush"));
    }

    #[test]
    fn error_display_invalid_path_with_reason() {
        let err = Error::InvalidPath {
            path: "no-slash".to_string(),
            reason: "must start with /".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("no-slash"));
        assert!(s.contains("must start with /"));
    }

    #[test]
    fn error_display_block_size_exceeded() {
        let err = Error::BlockSizeExceeded {
            path: "data/file".to_string(),
            size: 2_000_000,
            max: 1_048_576,
        };
        let s = err.to_string();
        assert!(s.contains("data/file"));
        assert!(s.contains("2000000"));
        assert!(s.contains("1048576"));
    }

    #[test]
    fn error_display_revoked_grant() {
        let err = Error::RevokedGrant("grant-123".to_string());
        assert!(err.to_string().contains("grant-123"));
    }

    #[test]
    fn error_display_transfer_failed() {
        let err = Error::TransferFailed("invalid token".to_string());
        assert!(err.to_string().contains("invalid token"));
    }

    #[test]
    fn error_display_access_denied() {
        let err = Error::AccessDenied {
            resource: "/private/docs".to_string(),
            reason: "no grant for this scope".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("/private/docs"));
        assert!(s.contains("no grant for this scope"));
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
    fn error_internal() {
        let err = Error::Internal("unexpected state".to_string());
        assert!(err.to_string().contains("unexpected state"));
    }

    #[test]
    fn error_deserialization_with_path() {
        let err = Error::Deserialization {
            path: "notes/001".to_string(),
            reason: "invalid CBOR".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("notes/001"));
        assert!(s.contains("invalid CBOR"));
    }

    #[test]
    fn error_sync_failed() {
        let err = Error::SyncFailed("reconciliation failed".to_string());
        assert!(err.to_string().contains("reconciliation failed"));
    }

    #[test]
    fn error_conflict() {
        let err = Error::Conflict("notes/doc".to_string());
        assert!(err.to_string().contains("notes/doc"));
    }
}
