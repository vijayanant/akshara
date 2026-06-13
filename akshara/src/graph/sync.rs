use std::sync::Arc;

use super::Graph;
use crate::error::Result;

use crate::sync::Conflict;

/// Report from a synchronization operation.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Number of graphs synchronized
    pub graphs_synced: usize,
    /// Number of manifests received
    pub manifests_received: usize,
    /// Number of blocks received
    pub blocks_received: usize,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Number of conflicts detected
    pub conflicts_detected: usize,
    /// List of detailed conflicts detected
    pub conflicts: Vec<Conflict>,
}

use crate::SyncMode;

impl Graph {
    pub async fn sync(&self, mode: SyncMode) -> Result<SyncReport> {
        let transport = Arc::new(crate::sync::MockTransport::new());
        let engine = crate::sync::SyncEngine::new(transport, self.vault.clone());
        engine
            .sync_graph(self.graph_id, &self.store, &self.graph_key, mode)
            .await
    }
}
