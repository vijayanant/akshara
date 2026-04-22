//! Sync engine for orchestrating graph synchronization.
//!
//! The SyncEngine coordinates between the transport layer and the protocol layer
//! to synchronize graphs with relays or peers.

use akshara_aadhaara::{GraphId, GraphStore, InMemoryStore, Reconciler};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::graph::SyncReport;
use crate::sync::transport::SyncTransport;
use crate::vault::Vault;

/// The SyncEngine manages the multi-step synchronization process.
pub struct SyncEngine {
    transport: Arc<dyn SyncTransport>,
    vault: Arc<dyn Vault>,
}

impl SyncEngine {
    /// Creates a new SyncEngine with the given transport and vault.
    pub fn new(transport: Arc<dyn SyncTransport>, vault: Arc<dyn Vault>) -> Self {
        Self { transport, vault }
    }

    /// Synchronize all graphs known to the client.
    ///
    /// Currently a stub - real implementation will walk the registry.
    pub async fn sync_all(&self, _store: &InMemoryStore) -> Result<SyncReport> {
        // TODO: Iterate over all graphs in the registry and sync them.
        // For now, return empty report
        Ok(SyncReport {
            graphs_synced: 0,
            manifests_received: 0,
            blocks_received: 0,
            bytes_transferred: 0,
            conflicts_detected: 0,
        })
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
        key: &akshara_aadhaara::GraphKey,
    ) -> Result<SyncReport> {
        // 1. Get local heads
        let local_heads = store
            .get_heads(&graph_id)
            .await
            .map_err(|e| Error::SyncFailed(format!("Failed to get local heads: {}", e)))?;

        // 2. Exchange heads with remote peer
        let peer_heads = self
            .transport
            .exchange_heads(graph_id, local_heads.clone())
            .await?;

        // 3. Reconcile to find missing data
        let reconciler = Reconciler::new(store);
        let comparison = reconciler
            .reconcile(&peer_heads, &local_heads)
            .await
            .map_err(|e| Error::SyncFailed(format!("Reconciliation failed: {}", e)))?;

        // Check if there's anything to sync
        let peer_surplus_len = comparison.peer_surplus.missing().len();
        let self_surplus_len = comparison.self_surplus.missing().len();

        if peer_surplus_len == 0 && self_surplus_len == 0 {
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

        // PRE-CALCULATED RITUALS:
        // Hoist all loop-invariant data to ensure maximum performance.
        let is_identity_sync = graph_id == self.vault.get_identity_id().await?;
        let latest_anchor = self.vault.latest_identity_anchor();

        let mut auditor = akshara_aadhaara::Auditor::new(store).with_graph_key(key.clone());
        if latest_anchor != akshara_aadhaara::ManifestId::null() {
            auditor = auditor.with_latest_identity(latest_anchor);
        }

        use futures::StreamExt;
        while let Some(portion_result) = portions_stream.next().await {
            let portion = portion_result
                .map_err(|e| Error::SyncFailed(format!("Portion stream error: {}", e)))?;

            let bytes = portion.data();
            bytes_transferred += bytes.len() as u64;

            if self
                .ingest_portion(&graph_id, portion, store, &mut auditor)
                .await?
            {
                manifests_received += 1;

                // If this is our own identity graph, update the vault's anchor immediately
                // so subsequent manifests in this turn can use the new authority state.
                if is_identity_sync {
                    // We need to peek at the CID we just stored
                    // TODO: Optimization - return CID from ingest_portion
                }
            } else {
                blocks_received += 1;
            }
        }

        // TODO: Push our surplus to peer if needed

        Ok(SyncReport {
            graphs_synced: 1,
            manifests_received,
            blocks_received,
            bytes_transferred,
            conflicts_detected: 0, // TODO: Detect conflicts
        })
    }

    /// Verifies, audits, and ingests a single portion into the store.
    /// Returns true if the portion was a manifest, false if it was a block.
    async fn ingest_portion(
        &self,
        graph_id: &GraphId,
        portion: akshara_aadhaara::Portion,
        store: &InMemoryStore,
        auditor: &mut akshara_aadhaara::Auditor<'_, InMemoryStore>,
    ) -> Result<bool> {
        let expected_id = portion.id();
        let bytes = portion.data();

        // 1. BLIND VERIFICATION: Recalculate hash before touching the DB
        let actual_id = akshara_aadhaara::Address::try_from(bytes).map_err(|_| {
            Error::SyncFailed(format!("Malformed data in portion for {}", expected_id))
        })?;

        if actual_id != *expected_id {
            return Err(Error::SyncFailed(format!(
                "CID mismatch: expected {}, got {}",
                expected_id, actual_id
            )));
        }

        // 2. DISPATCH BY TYPE
        if expected_id.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
            let manifest =
                akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Manifest>(bytes)
                    .map_err(|e| Error::SyncFailed(format!("Failed to parse manifest: {}", e)))?;

            // 3. AUTHORITY AUDIT
            auditor
                .audit_manifest(&manifest, Some(graph_id))
                .await
                .map_err(Error::Protocol)?;

            store
                .put_manifest(&manifest)
                .await
                .map_err(Error::Protocol)?;

            // Update vault if it's an identity update
            if *graph_id == self.vault.get_identity_id().await? {
                self.vault.update_identity_anchor(manifest.id());
            }

            Ok(true)
        } else {
            let block = akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(bytes)
                .map_err(|e| Error::SyncFailed(format!("Failed to parse block: {}", e)))?;

            // 4. INTEGRITY AUDIT
            auditor.audit_block(&block).map_err(Error::Protocol)?;

            store.put_block(&block).await.map_err(Error::Protocol)?;
            Ok(false)
        }
    }
}
