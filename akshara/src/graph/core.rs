use std::sync::Arc;
use zeroize::Zeroizing;

use crate::config::TuningConfig;
use crate::staging::InMemoryStagingStore;
use crate::vault::Vault;
use akshara_aadhaara::{GraphId, GraphKey, InMemoryStore};

#[derive(Debug, Clone)]
pub enum StateValue {
    Data(Vec<u8>),
    Link(akshara_aadhaara::Address),
}

/// Handle to a single graph for read/write operations.
///
/// The graph key is held in a `Zeroizing` wrapper and is zeroized on drop.
/// The vault is only accessed during cryptographic operations to minimize
/// secret key lifetime in memory.
pub struct Graph {
    pub(crate) graph_id: GraphId,
    pub(crate) graph_key: Zeroizing<GraphKey>,
    pub(crate) vault: Arc<dyn Vault>,
    pub(crate) store: InMemoryStore,
    pub(crate) staging: Arc<InMemoryStagingStore>,
    pub(crate) tuning: TuningConfig,
    pub(crate) flush_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Graph {
    /// Create a new graph handle.
    pub fn new(
        graph_id: GraphId,
        graph_key: GraphKey,
        vault: Arc<dyn Vault>,
        store: InMemoryStore,
        staging: Arc<InMemoryStagingStore>,
        tuning: TuningConfig,
    ) -> Self {
        Self {
            graph_id,
            graph_key: Zeroizing::new(graph_key),
            vault,
            store,
            staging,
            tuning,
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Get the graph ID.
    pub fn id(&self) -> GraphId {
        self.graph_id
    }

    /// Get the graph key.
    pub fn key(&self) -> &GraphKey {
        &self.graph_key
    }

    /// Get the storage backend.
    pub fn store(&self) -> &InMemoryStore {
        &self.store
    }
}
