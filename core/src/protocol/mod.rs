use crate::base::address::{BlockId, GraphId, ManifestId};
use serde::{Deserialize, Serialize};

pub mod engine;
pub use engine::SyncEngine;

/// A request to synchronize the graph state, containing the known heads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    graph_id: GraphId,
    heads: Vec<ManifestId>,
}

impl SyncRequest {
    pub fn new(graph_id: GraphId, heads: Vec<ManifestId>) -> Self {
        Self { graph_id, heads }
    }

    pub fn graph_id(&self) -> &GraphId {
        &self.graph_id
    }

    pub fn heads(&self) -> &[ManifestId] {
        &self.heads
    }
}

/// A response to a sync request, identifying the missing objects required
/// to reach the target state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    missing_manifests: Vec<ManifestId>,
    missing_blocks: Vec<BlockId>,
}

impl SyncResponse {
    pub fn new(missing_manifests: Vec<ManifestId>, missing_blocks: Vec<BlockId>) -> Self {
        Self {
            missing_manifests,
            missing_blocks,
        }
    }

    pub fn missing_manifests(&self) -> &[ManifestId] {
        &self.missing_manifests
    }

    pub fn missing_blocks(&self) -> &[BlockId] {
        &self.missing_blocks
    }
}

#[cfg(test)]
mod test_sync_engine;

#[cfg(test)]
mod test_sync_protocol;
