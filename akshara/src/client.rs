//! The Akshara client — main entry point for the API.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use akshara_aadhaara::{GraphId, GraphStore, InMemoryStore, Lakshana};

use crate::config::{ClientConfig, TuningConfig};
use crate::error::{Error, Result};
use crate::graph::{Graph, SyncReport};
use crate::staging::InMemoryStagingStore;
use crate::sync::{MockTransport, SyncEngine};
use crate::vault::{Vault, create_vault};

/// The main Akshara client.
///
/// `Client` is the entry point. It manages:
/// - A vault for identity and key storage
/// - A storage backend for blocks and manifests
/// - An in-memory staging buffer for write coalescing
/// - A registry of graphs known to this client
pub struct Client {
    vault: Arc<dyn Vault>,
    store: InMemoryStore,
    tuning: TuningConfig,
    graph_registry: Arc<RwLock<HashMap<GraphId, String>>>,
}

impl Client {
    /// Initialize the Akshara client.
    ///
    /// On first run, a 24-word mnemonic is generated and shown via the vault.
    /// **Write this down — there is no "forgot password."**
    pub async fn init(config: ClientConfig) -> Result<Self> {
        let vault_cfg = config.vault().clone();
        let tuning = config.tuning().clone();

        let vault = create_vault(vault_cfg)?;
        let _result = vault.initialize(None).await?;

        let store = InMemoryStore::new();
        let graph_registry = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            vault,
            store,
            tuning,
            graph_registry,
        })
    }

    /// Create a new graph with a randomly generated ID.
    ///
    /// The graph is encrypted with a key derived from your identity and the
    /// graph ID. Each graph gets its own staging store — operations never
    /// leak across graph boundaries.
    pub async fn create_graph(&self) -> Result<Graph> {
        let graph_id = GraphId::new();
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;
        let staging = Arc::new(InMemoryStagingStore::new());

        // Register in L1 registry (temporary: debug format of GraphId)
        let lakshana = format!("{:?}", graph_id);
        {
            let mut registry = self.graph_registry.write().await;
            registry.insert(graph_id, lakshana);
        }

        Ok(Graph::new(
            graph_id,
            graph_key,
            self.vault.clone(),
            self.store.clone(),
            staging,
            self.tuning.clone(),
        ))
    }

    /// Open an existing graph by its Lakshana.
    ///
    /// A Lakshana is an anonymous, HMAC-derived identifier that prevents
    /// relay-side graph clustering. In v0.1 we resolve it via deterministic
    /// truncation; full relay resolution is coming in v0.2.
    pub async fn open_graph(&self, lakshana_str: &str) -> Result<Graph> {
        let lakshana: Lakshana = lakshana_str
            .parse()
            .map_err(|_| Error::InvalidLakshana(lakshana_str.to_string()))?;

        let graph_id = GraphId::from(lakshana);
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;
        let staging = Arc::new(InMemoryStagingStore::new());

        // Register so the opened graph appears in discover_graphs
        {
            let mut registry = self.graph_registry.write().await;
            registry.insert(graph_id, lakshana_str.to_string());
        }

        Ok(Graph::new(
            graph_id,
            graph_key,
            self.vault.clone(),
            self.store.clone(),
            staging,
            self.tuning.clone(),
        ))
    }

    /// Discover all graphs this client has local state for.
    ///
    /// This is a local-only operation — no network or relay is contacted.
    /// The registry is snapshotted before I/O to avoid holding a read lock
    /// across async store lookups.
    pub async fn discover_graphs(&self) -> Result<Vec<GraphSummary>> {
        let entries: Vec<_> = {
            let registry = self.graph_registry.read().await;
            registry
                .iter()
                .map(|(id, lak)| (*id, lak.clone()))
                .collect()
        };

        let mut summaries = Vec::new();
        for (graph_id, lakshana) in &entries {
            let heads = self
                .store
                .get_heads(graph_id)
                .await
                .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

            summaries.push(GraphSummary {
                graph_id: *graph_id,
                lakshana: lakshana.clone(),
                manifest_count: heads.len(),
                last_flushed: None,
            });
        }

        Ok(summaries)
    }

    /// Synchronize all graphs with the relay.
    ///
    /// Currently uses `MockTransport` — real gRPC transport is coming in v0.2.
    pub async fn sync(&self) -> Result<SyncReport> {
        let transport = MockTransport::new();
        let engine = SyncEngine::new(transport, self.vault.clone());
        engine.sync_all(&self.store).await
    }

    /// Synchronize a specific graph.
    pub async fn sync_graph(&self, graph_id: GraphId) -> Result<SyncReport> {
        let transport = MockTransport::new();
        let engine = SyncEngine::new(transport, self.vault.clone());
        engine.sync_graph(graph_id, &self.store).await
    }

    /// Remove a graph from the local registry.
    ///
    /// Note: this removes the graph from discovery but does not yet clear
    /// block/manifest data from the store.
    pub async fn forget_graph(&self, graph_id: GraphId) -> Result<()> {
        {
            let mut registry = self.graph_registry.write().await;
            registry.remove(&graph_id);
        }
        Ok(())
    }

    /// Returns the vault handle for vault-specific operations.
    pub fn vault(&self) -> &Arc<dyn Vault> {
        &self.vault
    }
}

/// Summary information for a discovered graph.
#[derive(Debug, Clone)]
pub struct GraphSummary {
    pub graph_id: GraphId,
    pub lakshana: String,
    pub manifest_count: usize,
    pub last_flushed: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use akshara_aadhaara::SecretIdentity;

    async fn create_test_client() -> Client {
        let _mnemonic = SecretIdentity::generate_mnemonic().unwrap();
        let config = ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage();
        // We need to initialize the vault with the mnemonic for tests
        // For now, use the standard init path
        Client::init(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_graph() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();
        assert!(!graph.id().to_string().is_empty());
    }

    #[tokio::test]
    async fn test_discover_graphs_empty() {
        let client = create_test_client().await;
        let graphs = client.discover_graphs().await.unwrap();
        assert!(graphs.is_empty());
    }

    #[tokio::test]
    async fn test_discover_graphs_after_create() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();

        // Graph is registered immediately (L1 registry), even before flush
        let graphs = client.discover_graphs().await.unwrap();
        assert_eq!(graphs.len(), 1);
        assert_eq!(graphs[0].graph_id, graph.id());
        assert_eq!(graphs[0].manifest_count, 0); // No manifests until flush
    }

    #[tokio::test]
    async fn test_forget_graph() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();
        let graph_id = graph.id();

        // Forget should not error even with no data
        client.forget_graph(graph_id).await.unwrap();
    }

    #[tokio::test]
    async fn open_graph_rejects_invalid_lakshana() {
        // A typo in the lakshana must give a clean error, not panic or open
        // a garbage graph.
        let client = create_test_client().await;
        let result = client.open_graph("not-a-valid-lakshana!!!").await;
        assert!(
            matches!(result, Err(Error::InvalidLakshana(_))),
            "Expected InvalidLakshana for garbage input"
        );
    }

    #[tokio::test]
    async fn discover_graphs_tracks_all_created_graphs() {
        // Verify that create_graph properly registers graphs and that
        // discover_graphs returns them. This guards against the registry
        // and graph creation getting out of sync.
        let client = create_test_client().await;

        let g1 = client.create_graph().await.unwrap();
        let g2 = client.create_graph().await.unwrap();

        let all = client.discover_graphs().await.unwrap();
        assert_eq!(all.len(), 2);

        let ids: Vec<_> = all.iter().map(|s| s.graph_id).collect();
        assert!(ids.contains(&g1.id()));
        assert!(ids.contains(&g2.id()));
    }
}
