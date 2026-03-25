//! The Akshara client - main entry point for the API.

use std::sync::Arc;

use akshara_aadhaara::{GraphId, InMemoryStore, SigningPublicKey};

use crate::config::ClientConfig;
use crate::config::TuningConfig;
use crate::error::{Error, Result};
use crate::graph::{Graph, SyncReport};
use crate::staging::{InMemoryStagingStore, StagingStore};
use crate::sync::{MockTransport, SyncEngine};
use crate::vault::{Vault, create_vault};

/// The main Akshara client.
pub struct Client {
    vault: Arc<dyn Vault>,
    store: InMemoryStore,
    staging: Arc<Mutex<Box<dyn StagingStore>>>,
    tuning: TuningConfig,
    root_key: SigningPublicKey,
}

impl Client {
    /// Initialize the Akshara client.
    pub async fn init(config: ClientConfig) -> Result<Self> {
        // Create vault (takes ownership of config.vault)
        let vault = create_vault(config.vault)?;

        // Initialize vault (generates mnemonic if not exists)
        let _result = vault.initialize(None).await?;

        // Get root key for sync verification
        let identity = vault.get_identity().await?;
        let root_key = identity.public().signing_key().clone();

        // Create in-memory store
        let store = InMemoryStore::new();

        // Create staging store
        let staging: Box<dyn StagingStore> = Box::new(InMemoryStagingStore::new());

        Ok(Self {
            vault,
            store,
            staging: Arc::new(Mutex::new(staging)),
            tuning: config.tuning,
            root_key,
        })
    }

    /// Create a new graph.
    ///
    /// The graph ID is randomly generated. The graph is encrypted with a unique key
    /// derived from your identity.
    pub async fn create_graph(&self) -> Result<Graph> {
        let graph_id = GraphId::new();

        // Get graph key from vault
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;

        Ok(Graph::new(
            graph_id,
            graph_key,
            self.vault.clone(),
            self.store.clone(),
            self.staging.clone(),
            self.tuning.clone(),
        ))
    }

    /// Open an existing graph by its Lakshana.
    pub async fn open_graph(&self, lakshana: &str) -> Result<Graph> {
        // TODO: Resolve Lakshana to GraphId
        // For now, parse as GraphId directly
        let graph_id: GraphId = lakshana
            .parse()
            .map_err(|_| Error::GraphNotFound(lakshana.to_string()))?;

        // Get graph key from vault
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;

        Ok(Graph::new(
            graph_id,
            graph_key,
            self.vault.clone(),
            self.store.clone(),
            self.staging.clone(),
            self.tuning.clone(),
        ))
    }

    /// List all graphs the user has access to.
    pub async fn list_graphs(&self) -> Result<Vec<GraphSummary>> {
        // TODO: Implement graph discovery
        Ok(Vec::new())
    }

    /// Synchronize all graphs with the relay.
    pub async fn sync(&self) -> Result<SyncReport> {
        // Use mock transport for demos (no real network)
        let transport = MockTransport::new();
        let engine = SyncEngine::new(transport, self.root_key.clone());
        engine.sync_all(&self.store).await
    }

    /// Synchronize a specific graph.
    pub async fn sync_graph(&self, graph_id: GraphId) -> Result<SyncReport> {
        // Use mock transport for demos (no real network)
        let transport = MockTransport::new();
        let engine = SyncEngine::new(transport, self.root_key.clone());
        engine.sync_graph(graph_id, &self.store).await
    }
}

/// Summary of a graph.
#[derive(Debug, Clone)]
pub struct GraphSummary {
    /// The graph ID
    pub graph_id: GraphId,
    /// Optional name/label
    pub name: Option<String>,
    /// Lakshana for discovery
    pub lakshana: String,
    /// Number of manifests
    pub manifest_count: usize,
    /// Last sync timestamp
    pub last_synced: Option<u64>,
}
