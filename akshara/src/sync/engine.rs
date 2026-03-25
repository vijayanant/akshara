//! Sync engine for orchestrating graph synchronization.
//!
//! The SyncEngine coordinates between the transport layer and the protocol layer
//! to synchronize graphs with relays or peers.

use akshara_aadhaara::{GraphId, GraphStore, InMemoryStore, Reconciler, SigningPublicKey};

use super::transport::SyncTransport;
use crate::error::{Error, Result};
use crate::graph::SyncReport;

/// SyncEngine orchestrates graph synchronization.
///
/// It coordinates between:
/// - Transport layer (network/IPC communication)
/// - Protocol layer (reconciliation mathematics from aadhaara)
/// - Storage layer (local graph state)
pub struct SyncEngine<T: SyncTransport> {
    transport: T,
    root_key: SigningPublicKey,
}

impl<T: SyncTransport> SyncEngine<T> {
    /// Create a new sync engine with the given transport.
    pub fn new(transport: T, root_key: SigningPublicKey) -> Self {
        Self { transport, root_key }
    }

    /// Synchronize a single graph with the remote peer.
    ///
    /// This performs a full sync turn:
    /// 1. Get local heads from store
    /// 2. Exchange heads with remote peer
    /// 3. Reconcile to find missing data
    /// 4. Request missing portions
    /// 5. Converge (apply portions to local store)
    /// 6. Return sync report
    pub async fn sync_graph(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
    ) -> Result<SyncReport> {
        // 1. Get local heads
        let local_heads = store
            .get_heads(&graph_id)
            .await
            .map_err(|e| Error::SyncFailed(format!("Failed to get local heads: {}", e)))?;

        // If no local heads, we're starting fresh
        let local_heads = if local_heads.is_empty() {
            vec![]
        } else {
            local_heads
        };

        // 2. Exchange heads with remote peer
        let peer_heads = self
            .transport
            .exchange_heads(graph_id, local_heads.clone())
            .await?;

        // 3. Reconcile to find missing data
        let reconciler = Reconciler::new(store, self.root_key.clone());
        let comparison = reconciler
            .reconcile(&peer_heads, &local_heads)
            .await
            .map_err(|e| Error::SyncFailed(format!("Reconciliation failed: {}", e)))?;

        // Check if there's anything to sync
        let peer_surplus_len = comparison.peer_surplus.missing().len();
        let self_surplus_len = comparison.self_surplus.missing().len();

        if peer_surplus_len == 0 && self_surplus_len == 0 {
            // Already in sync
            return Ok(SyncReport {
                graphs_synced: 1,
                manifests_received: 0,
                blocks_received: 0,
                bytes_transferred: 0,
                conflicts_detected: 0,
            });
        }

        // 4. Request missing portions from peer
        let mut portions_stream = self
            .transport
            .request_portions(&comparison.peer_surplus)
            .await?;

        // 5. Converge (apply portions to local store)
        // For now, we just consume the stream
        // TODO: Actually apply portions to store
        let mut manifests_received = 0;
        let mut blocks_received = 0;
        let mut bytes_transferred = 0;

        use futures::StreamExt;
        while let Some(_portion_result) = portions_stream.next().await {
            // TODO: Handle portion and apply to store
            manifests_received += 1;
        }

        // TODO: Push our surplus to peer if needed
        if self_surplus_len > 0 {
            // TODO: Implement push_portions
        }

        Ok(SyncReport {
            graphs_synced: 1,
            manifests_received,
            blocks_received,
            bytes_transferred,
            conflicts_detected: 0, // TODO: Detect conflicts
        })
    }

    /// Synchronize all graphs known to the store.
    ///
    /// This is a convenience method that syncs all graphs.
    pub async fn sync_all(&self, _store: &InMemoryStore) -> Result<SyncReport> {
        // TODO: Implement multi-graph sync
        // For now, return empty report
        Ok(SyncReport {
            graphs_synced: 0,
            manifests_received: 0,
            blocks_received: 0,
            bytes_transferred: 0,
            conflicts_detected: 0,
        })
    }
}
