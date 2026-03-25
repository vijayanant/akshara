//! The Akshara client - main entry point for the API.

use std::sync::Arc;
use tokio::sync::Mutex;

use akshara_aadhaara::{GraphId, InMemoryStore, Lakshana, SigningPublicKey};

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
    pub async fn create_graph(&self, _name: &str) -> Result<Graph> {
        let graph_id = GraphId::new();

        // Get graph key from vault
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;

        // Get current identity anchor
        let identity_anchor = self.vault.latest_identity_anchor();

        Ok(Graph::new(
            graph_id,
            graph_key,
            identity_anchor,
            self.vault.clone(),
            self.store.clone(),
            self.staging.clone(),
            self.tuning.clone(),
        ))
    }

    /// Open an existing graph by its Lakshana.
    pub async fn open_graph(&self, lakshana_str: &str) -> Result<Graph> {
        let lakshana: Lakshana = lakshana_str
            .parse()
            .map_err(|_| Error::GraphNotFound(lakshana_str.to_string()))?;

        // TODO: Resolve Lakshana to actual GraphId via Relay
        // For now, we perform a deterministic truncation for the demo/prototype
        let graph_id = GraphId::from(lakshana);

        // Get graph key from vault
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;

        // Get current identity anchor
        let identity_anchor = self.vault.latest_identity_anchor();

        Ok(Graph::new(
            graph_id,
            graph_key,
            identity_anchor,
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
        let engine = SyncEngine::new(transport, self.vault.clone(), self.root_key.clone());
        engine.sync_all(&self.store).await
    }

    /// Synchronize a specific graph.
    pub async fn sync_graph(&self, graph_id: GraphId) -> Result<SyncReport> {
        // Use mock transport for demos (no real network)
        let transport = MockTransport::new();
        let engine = SyncEngine::new(transport, self.vault.clone(), self.root_key.clone());
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
