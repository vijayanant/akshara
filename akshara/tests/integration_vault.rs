//! Integration tests for the Akshara vault module.
//!
//! These tests verify vault behavior across multiple components.

use std::sync::Arc;

use akshara::vault::{EphemeralVault, Vault, VaultConfig, create_vault};
use akshara_aadhaara::GraphId;
use proptest::prelude::*;

// ============================================================================
// Property-Based Tests
// ============================================================================

proptest! {
    #[test]
    fn vault_sign_always_64_bytes(
        data in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let vault = EphemeralVault::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            vault.initialize(None).await.unwrap();
            let signature = vault.sign(&data).await.unwrap();
            assert_eq!(signature.len(), 64);
        });
    }
}

// ============================================================================
// Multi-Component Integration Tests
// ============================================================================

#[tokio::test]
async fn vault_derive_graph_key_deterministic() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let graph_id = GraphId::new();
    let key1 = vault.derive_graph_key(&graph_id).await.unwrap();
    let key2 = vault.derive_graph_key(&graph_id).await.unwrap();

    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[tokio::test]
async fn vault_derive_graph_key_different_graphs() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let graph_id1 = GraphId::new();
    let graph_id2 = GraphId::new();

    let key1 = vault.derive_graph_key(&graph_id1).await.unwrap();
    let key2 = vault.derive_graph_key(&graph_id2).await.unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[tokio::test]
async fn vault_sign_deterministic() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let data = b"test message";
    let sig1 = vault.sign(data).await.unwrap();
    let sig2 = vault.sign(data).await.unwrap();

    assert_eq!(sig1, sig2);
}

#[tokio::test]
async fn vault_sign_different_data() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let data1 = b"message 1";
    let data2 = b"message 2";

    let sig1 = vault.sign(data1).await.unwrap();
    let sig2 = vault.sign(data2).await.unwrap();

    assert_ne!(sig1, sig2);
}

#[tokio::test]
async fn vault_identity_consistency() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let identity1 = vault.get_identity().await.unwrap();
    let identity2 = vault.get_identity().await.unwrap();

    assert_eq!(
        identity1.public().signing_key().to_hex(),
        identity2.public().signing_key().to_hex()
    );
}

#[tokio::test]
async fn vault_clear_clears_sensitive_data() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    vault.clear();

    assert!(!vault.is_initialized());
}

#[test]
fn create_vault_ephemeral() {
    let vault = create_vault(VaultConfig::Ephemeral).unwrap();
    assert!(!vault.is_initialized());
}

#[test]
fn create_vault_custom() {
    let custom_vault = Arc::new(EphemeralVault::new());
    let vault = create_vault(VaultConfig::Custom {
        backend: custom_vault,
    })
    .unwrap();
    assert!(!vault.is_initialized());
}

#[tokio::test]
async fn vault_sign_empty_data() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let data = b"";
    let signature = vault.sign(data).await.unwrap();
    assert_eq!(signature.len(), 64);
}

#[tokio::test]
async fn vault_sign_large_data() {
    let vault = EphemeralVault::new();
    vault.initialize(None).await.unwrap();

    let data = vec![0u8; 1024];
    let signature = vault.sign(&data).await.unwrap();
    assert_eq!(signature.len(), 64);
}
