use crate::base::address::{Address, GraphId, ManifestId};
use serde::{Deserialize, Serialize};

pub(crate) mod engine;
pub use engine::Reconciler;

/// `Heads` represents the frontier of absolute cryptographic truth for a graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heads {
    pub(crate) graph_id: GraphId,
    pub(crate) heads: Vec<ManifestId>,
}

impl Heads {
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

/// `Delta` represents a specific state of absence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Delta {
    pub(crate) missing: Vec<Address>,
}

impl Delta {
    pub fn new(missing: Vec<Address>) -> Self {
        Self { missing }
    }

    pub fn missing(&self) -> &[Address] {
        &self.missing
    }

    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
    }
}

/// `Comparison` represents the bi-directional knowledge gap between two peers.
///
/// It identifies what each peer possesses that the other lacks, enabling
/// total symmetric convergence in a single exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    /// Items present in the peer's frontier but absent locally (Needs download).
    pub peer_surplus: Delta,
    /// Items present locally but absent in the peer's frontier (Needs upload).
    pub self_surplus: Delta,
}

/// `Portion` is the atomic unit of data delivered to fill a Delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Portion {
    pub(crate) id: Address,
    pub(crate) data: Vec<u8>,
}

impl Portion {
    pub fn new(id: Address, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    pub fn id(&self) -> &Address {
        &self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod test_sync_engine;

#[cfg(test)]
mod test_sync_protocol;
