//! Sync engine for orchestrating graph synchronization.
//!
//! The SyncEngine coordinates between the transport layer and the protocol layer
//! to synchronize graphs with relays or peers.

use akshara_aadhaara::{Address, GraphId, GraphStore, InMemoryStore, Portion, Reconciler};
use futures::stream::{self, Stream};
use std::pin::Pin;
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
                .ingest_portion(&graph_id, portion, store, &mut auditor, is_identity_sync)
                .await?
            {
                manifests_received += 1;
            } else {
                blocks_received += 1;
            }
        }

        // 6. Push local surplus to peer
        let self_missing = comparison.self_surplus.missing().to_vec();
        if !self_missing.is_empty() {
            let push_stream = self.stream_surplus(store, self_missing).await;

            // We need to track how many bytes we are pushing
            // For now, we'll just send the stream and assume success
            self.transport.push_portions(push_stream).await?;

            // TODO: Accurate bytes_transferred update for push
        }

        // 7. Conflict detection
        let conflicts_detected = if !comparison.peer_surplus.missing().is_empty()
            && !comparison.self_surplus.missing().is_empty()
        {
            // ALPHA: Simple heuristic - if both sides have surplus, there might be a fork
            // In v0.2 we'll use actual LCA analysis.
            1
        } else {
            0
        };

        Ok(SyncReport {
            graphs_synced: 1,
            manifests_received,
            blocks_received,
            bytes_transferred,
            conflicts_detected,
        })
    }

    /// Verifies, audits, and ingests a single portion into the store.
    async fn ingest_portion(
        &self,
        graph_id: &GraphId,
        portion: Portion,
        store: &InMemoryStore,
        auditor: &mut akshara_aadhaara::Auditor<'_, InMemoryStore>,
        is_identity_sync: bool,
    ) -> Result<bool> {
        let expected_id = portion.id();
        let bytes = portion.data();

        let actual_id = Address::try_from(bytes).map_err(|_| {
            Error::SyncFailed(format!("Malformed data in portion for {}", expected_id))
        })?;

        if actual_id != *expected_id {
            return Err(Error::SyncFailed(format!(
                "CID mismatch: expected {}, got {}",
                expected_id, actual_id
            )));
        }

        if expected_id.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
            let manifest =
                akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Manifest>(bytes)
                    .map_err(|e| Error::SyncFailed(format!("Failed to parse manifest: {}", e)))?;

            auditor
                .audit_manifest(&manifest, Some(graph_id))
                .await
                .map_err(Error::Protocol)?;

            store
                .put_manifest(&manifest)
                .await
                .map_err(Error::Protocol)?;

            if is_identity_sync {
                self.vault.update_identity_anchor(manifest.id());
            }

            Ok(true)
        } else {
            let block = akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(bytes)
                .map_err(|e| Error::SyncFailed(format!("Failed to parse block: {}", e)))?;

            auditor.audit_block(&block).map_err(Error::Protocol)?;

            store.put_block(&block).await.map_err(Error::Protocol)?;
            Ok(false)
        }
    }

    /// Streams local missing data for pushing to peer.
    async fn stream_surplus(
        &self,
        store: &InMemoryStore,
        missing: Vec<Address>,
    ) -> Pin<Box<dyn Stream<Item = Result<Portion>> + Send>> {
        let store = store.clone();

        let s = stream::unfold((store, missing), |(store, mut missing)| async move {
            if missing.is_empty() {
                return None;
            }
            let addr = missing.remove(0);

            let res = if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                let mid = akshara_aadhaara::ManifestId::try_from(addr).unwrap();
                match store.get_manifest(&mid).await {
                    Ok(Some(m)) => akshara_aadhaara::to_canonical_bytes(&m)
                        .map(|bytes| Portion::new(addr, bytes))
                        .map_err(Error::Protocol),
                    Ok(None) => Err(Error::Internal(format!(
                        "Manifest {} missing during push",
                        mid
                    ))),
                    Err(e) => Err(Error::Protocol(e)),
                }
            } else {
                let bid = akshara_aadhaara::BlockId::try_from(addr).unwrap();
                match store.get_block(&bid).await {
                    Ok(Some(b)) => akshara_aadhaara::to_canonical_bytes(&b)
                        .map(|bytes| Portion::new(addr, bytes))
                        .map_err(Error::Protocol),
                    Ok(None) => Err(Error::Internal(format!(
                        "Block {} missing during push",
                        bid
                    ))),
                    Err(e) => Err(Error::Protocol(e)),
                }
            };

            Some((res, (store, missing)))
        });

        Box::pin(s)
    }
}
