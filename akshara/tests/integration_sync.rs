//! Integration tests for sync module.

use akshara::sync::{MockTransport, SyncEngine, SyncTransport};
use akshara_aadhaara::{GraphId, InMemoryStore, SecretIdentity};

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
    let transport = MockTransport::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let root_key = identity.public().signing_key().clone();

    let _engine = SyncEngine::new(transport, root_key);
    // Test that engine can be created
}

#[tokio::test]
async fn sync_engine_sync_graph_empty_store() {
    let transport = MockTransport::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let root_key = identity.public().signing_key().clone();
    let store = InMemoryStore::new();

    let engine = SyncEngine::new(transport, root_key);
    let graph_id = GraphId::new();

    let report = engine.sync_graph(graph_id, &store).await.unwrap();

    assert_eq!(report.graphs_synced, 1);
    assert_eq!(report.manifests_received, 0);
    assert_eq!(report.blocks_received, 0);
    assert_eq!(report.bytes_transferred, 0);
    assert_eq!(report.conflicts_detected, 0);
}

#[tokio::test]
async fn sync_engine_sync_all_empty_store() {
    let transport = MockTransport::new();
    let identity = SecretIdentity::generate(&mut rand::rngs::OsRng);
    let root_key = identity.public().signing_key().clone();
    let store = InMemoryStore::new();

    let engine = SyncEngine::new(transport, root_key);

    let report = engine.sync_all(&store).await.unwrap();

    assert_eq!(report.graphs_synced, 0);
    assert_eq!(report.manifests_received, 0);
}

// ============================================================================
// Conflict Types Tests
// ============================================================================

#[test]
fn merge_strategy_default_is_keep_latest() {
    let strategy = akshara::MergeStrategy::default();
    assert!(matches!(strategy, akshara::MergeStrategy::KeepLatest));
}

#[test]
fn merge_strategy_variants() {
    // Test all variants can be created
    let _latest = akshara::MergeStrategy::KeepLatest;
    let _mine = akshara::MergeStrategy::KeepMine;
    let _theirs = akshara::MergeStrategy::KeepTheirs;
    let _manual = akshara::MergeStrategy::Manual {
        resolver_name: "test".to_string(),
    };
}

#[test]
fn conflict_struct() {
    let graph_id = GraphId::new();
    let conflict = akshara::Conflict {
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
    let report = client.sync().await.unwrap();

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
