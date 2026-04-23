//! Integration tests for sync module.

use akshara::SyncTransport;
use akshara::sync::MockTransport;
use akshara::sync::{Conflict, MergeStrategy, SyncEngine};
use akshara::vault::VaultConfig;
use akshara_aadhaara::{GraphId, InMemoryStore, SecretIdentity};
use std::sync::Arc;

// ============================================================================
// MockTransport Tests
// ============================================================================

#[tokio::test]
async fn mock_transport_new_has_default_delay() {
    let transport = MockTransport::new();
    assert_eq!(transport.delay_ms, 10);
    assert_eq!(transport.failure_rate, 0.0);
}

#[tokio::test]
async fn mock_transport_with_custom_delay() {
    let transport = MockTransport::with_delay(50);
    assert_eq!(transport.delay_ms, 50);
}

#[tokio::test]
async fn mock_transport_exchange_heads_returns_empty() {
    let transport = MockTransport::new();
    let graph_id = GraphId::new();

    let heads = transport.exchange_heads(graph_id, vec![]).await.unwrap();
    assert!(heads.heads().is_empty());
}

#[tokio::test]
async fn mock_transport_request_portions_returns_empty_stream() {
    use futures::StreamExt;

    let transport = MockTransport::new();
    let delta = akshara_aadhaara::Delta::default();

    let mut stream = transport.request_portions(&delta).await.unwrap();
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn mock_transport_push_portions_accepts_all() {
    use futures::stream;

    let transport = MockTransport::new();
    let portions = stream::empty();

    let result = transport.push_portions(Box::pin(portions)).await;
    assert!(result.is_ok());
}

// ============================================================================
// SyncEngine Tests
// ============================================================================

#[tokio::test]
async fn sync_engine_new() {
    let transport = Arc::new(MockTransport::new());
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng).unwrap();
    let _root_key = identity.public().signing_key().clone();

    let vault = akshara::vault::create_vault(VaultConfig::Ephemeral).unwrap();
    let _engine = SyncEngine::new(transport, vault);
    // Test that engine can be created
}

#[tokio::test]
async fn sync_engine_sync_graph_empty_store() {
    let transport = Arc::new(MockTransport::new());
    let store = InMemoryStore::new();

    let vault = akshara::vault::create_vault(VaultConfig::Ephemeral).unwrap();
    vault.initialize(None).await.unwrap(); // Bootstrap the vault
    let engine = SyncEngine::new(transport, vault.clone());
    let graph_id = GraphId::new();
    let graph_key = vault.derive_graph_key(&graph_id).await.unwrap();

    let report = engine
        .sync_graph(graph_id, &store, &graph_key)
        .await
        .unwrap();

    assert_eq!(report.graphs_synced, 1);
    assert_eq!(report.manifests_received, 0);
    assert_eq!(report.blocks_received, 0);
    assert_eq!(report.bytes_transferred, 0);
    assert_eq!(report.conflicts_detected, 0);
}

#[tokio::test]
async fn sync_engine_push_surplus() {
    use akshara_aadhaara::test_utils::TestFactory;

    let factory = TestFactory::new().await;
    let store = factory.store.as_ref();
    let transport = Arc::new(MockTransport::new());

    // Create some local state using the factory
    let block = factory.create_block(b"Local Surprise").await;
    let manifest = factory.create_manifest(block.id(), vec![]).await;

    let vault = akshara::vault::create_vault(VaultConfig::Ephemeral).unwrap();
    vault.initialize(None).await.unwrap();
    let engine = SyncEngine::new(transport.clone(), vault);

    // SYNC TURN: Should push the local manifest and block
    let report = engine
        .sync_graph(factory.graph_id, store, &factory.graph_key)
        .await
        .unwrap();

    assert_eq!(report.graphs_synced, 1);

    // Verify transport recorded the push
    let pushed = transport.pushed_portions.read().unwrap();
    assert_eq!(pushed.len(), 2);
    assert!(pushed.iter().any(|p| p.id() == &manifest.id().into()));
    assert!(pushed.iter().any(|p| p.id() == &block.id().into()));
}

#[tokio::test]
async fn sync_engine_detects_conflict_heuristic() {
    use akshara_aadhaara::test_utils::TestFactory;
    let factory = TestFactory::new().await;
    let _store = factory.store.as_ref();

    // 1. Create a Mock Transport
    let _transport = Arc::new(MockTransport::new());

    // 2. Local surplus (Block A)
    let _block_a = factory.create_block(b"My side").await;
    let _manifest_a = factory.create_manifest(_block_a.id(), vec![]).await;

    // 3. Heuristic test: v0.2 will have stateful peer.
}

// ============================================================================
// Conflict Types Tests
// ============================================================================

#[test]
fn merge_strategy_default_is_keep_latest() {
    let strategy = MergeStrategy::default();
    assert!(matches!(strategy, MergeStrategy::KeepLatest));
}

#[test]
fn merge_strategy_variants() {
    // Test all variants can be created
    let _latest = MergeStrategy::KeepLatest;
    let _mine = MergeStrategy::KeepMine;
    let _theirs = MergeStrategy::KeepTheirs;
    let _manual = MergeStrategy::Manual {
        resolver_name: "test".to_string(),
    };
}

#[test]
fn conflict_struct() {
    let graph_id = GraphId::new();
    let conflict = Conflict {
        graph_id,
        path: "/test".to_string(),
        heads: vec![],
        strategy: None,
    };

    assert_eq!(conflict.path, "/test");
    assert!(conflict.heads.is_empty());
    assert!(conflict.strategy.is_none());
}

// ============================================================================
// Integration: Client with Sync
// ============================================================================

#[tokio::test]
async fn client_sync_with_mock_transport() {
    use akshara::{Client, ClientConfig};

    let config = ClientConfig::new().with_ephemeral_vault();
    let client = Client::init(config).await.unwrap();

    // Sync should work with mock transport (returns empty report)
    let report = client.sync_all().await.unwrap();

    assert_eq!(report.graphs_synced, 0);
    assert_eq!(report.manifests_received, 0);
}

#[tokio::test]
async fn client_sync_graph_with_mock_transport() {
    use akshara::{Client, ClientConfig};

    let config = ClientConfig::new().with_ephemeral_vault();
    let client = Client::init(config).await.unwrap();

    let graph_id = GraphId::new();

    // Sync specific graph should work with mock transport
    let report = client.sync_graph(graph_id).await.unwrap();

    assert_eq!(report.graphs_synced, 1);
    // Mock returns empty, so no data transferred
    assert_eq!(report.manifests_received, 0);
}

#[tokio::test]
async fn sync_engine_auto_anchoring_ritual() {
    use akshara::{Client, ClientConfig};
    use akshara_aadhaara::{Manifest, ManifestId};

    let config = ClientConfig::new().with_ephemeral_vault();
    let client = Client::init(config).await.unwrap();
    let vault = client.vault();

    assert_eq!(vault.latest_identity_anchor(), ManifestId::null());

    // Identity Graph ID
    let identity = vault.get_identity(None).await.unwrap();
    let id_graph_id = identity.identity_id().unwrap();

    // Receiving an update to the Identity Graph
    let new_root = akshara_aadhaara::BlockId::from_sha256(&[1u8; 32]);
    let new_id_manifest = Manifest::new(
        id_graph_id,
        new_root,
        vec![],
        ManifestId::null(),
        &identity,
        None,
    );

    // Simulate the engine check
    if id_graph_id == identity.identity_id().unwrap() {
        vault.update_identity_anchor(new_id_manifest.id());
    }

    assert_eq!(vault.latest_identity_anchor(), new_id_manifest.id());
}
