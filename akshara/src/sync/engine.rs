//! Sync engine for orchestrating graph synchronization.
//!
//! The SyncEngine coordinates between the transport layer and the protocol layer
//! to synchronize graphs with relays or peers.

use akshara_aadhaara::{GraphId, GraphStore, InMemoryStore, Reconciler, SigningPublicKey};
use std::sync::Arc;

use super::transport::SyncTransport;
use crate::error::{Error, Result};
use crate::graph::SyncReport;
use crate::vault::Vault;

/// SyncEngine orchestrates graph synchronization.
///
/// It coordinates between:
/// - Transport layer (network/IPC communication)
/// - Protocol layer (reconciliation mathematics from aadhaara)
/// - Storage layer (local graph state)
pub struct SyncEngine<T: SyncTransport> {
    transport: T,
    vault: Arc<dyn Vault>,
    root_key: SigningPublicKey,
}

impl<T: SyncTransport> SyncEngine<T> {
    /// Create a new sync engine with the given transport.
    pub fn new(transport: T, vault: Arc<dyn Vault>, root_key: SigningPublicKey) -> Self {
        Self {
            transport,
            vault,
            root_key,
        }
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
    pub async fn sync_graph(&self, graph_id: GraphId, store: &InMemoryStore) -> Result<SyncReport> {
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
        let mut manifests_received = 0;
        let mut blocks_received = 0;
        let mut bytes_transferred = 0;

        use futures::StreamExt;
        while let Some(portion_result) = portions_stream.next().await {
            let portion = portion_result
                .map_err(|e| Error::SyncFailed(format!("Portion stream error: {}", e)))?;

            // THE BLIND VERIFICATION MANDATE:
            // Recalculate CID before ingestion to prevent Relay-side poisoning.
            let bytes = portion.data();

            // Check codec from the portion's ID
            let expected_cid = portion.id();
            let actual_cid = akshara_aadhaara::Address::try_from(bytes).map_err(|_| {
                Error::SyncFailed(format!("Malformed data in portion for {}", expected_cid))
            })?;
            if actual_cid != *expected_cid {
                return Err(Error::SyncFailed(format!(
                    "CID mismatch: expected {}, got {}",
                    expected_cid, actual_cid
                )));
            }

            // Ingest into store
            if expected_cid.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                let manifest =
                    akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Manifest>(bytes)
                        .map_err(|e| {
                            Error::SyncFailed(format!("Failed to parse manifest: {}", e))
                        })?;

                // THE AUTHORITY AUDIT: Verify the author's right to speak before ingestion
                let latest_id = self.vault.latest_identity_anchor();
                let mut auditor = akshara_aadhaara::Auditor::new(store, self.root_key.clone());
                if latest_id != akshara_aadhaara::ManifestId::null() {
                    auditor = auditor.with_latest_identity(latest_id);
                }

                auditor.audit_manifest(&manifest).await.map_err(|e| {
                    Error::SyncFailed(format!(
                        "Authority audit failed for {}: {}",
                        expected_cid, e
                    ))
                })?;

                store
                    .put_manifest(&manifest)
                    .await
                    .map_err(|e| Error::SyncFailed(format!("Failed to store manifest: {}", e)))?;
                manifests_received += 1;

                // UPDATE ANCHOR: If this is an identity graph update, track the new anchor
                // We identify the identity graph by checking if it matches the user's discovery ID
                let identity = self.vault.get_identity().await?;
                // The identity graph's Lakshana is derived without a GraphId context
                let id_lakshana =
                    identity.derive_discovery_id(&akshara_aadhaara::GraphId::null())?;

                // For now, we assume graph_id mapping is active (prototype simplification)
                // In a full implementation, we'd check against the actual Lakshana being synced.
                if graph_id == akshara_aadhaara::GraphId::from(id_lakshana) {
                    self.vault.update_identity_anchor(manifest.id());
                }
            } else {
                let block =
                    akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(bytes)
                        .map_err(|e| Error::SyncFailed(format!("Failed to parse block: {}", e)))?;

                store
                    .put_block(&block)
                    .await
                    .map_err(|e| Error::SyncFailed(format!("Failed to store block: {}", e)))?;
                blocks_received += 1;
            }

            bytes_transferred += bytes.len() as u64;
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
