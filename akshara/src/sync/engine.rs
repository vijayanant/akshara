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

        // 4. Request missing portions from remote, recursively discovering nested blocks via Merkle Tree index decryption
        use std::collections::{HashMap, HashSet};
        let mut fetched = HashSet::new();
        let mut to_fetch: HashSet<Address> =
            comparison.peer_surplus.missing().iter().cloned().collect();
        let mut block_graph_ids = HashMap::new();

        let mut fetched_manifests = Vec::new();
        let mut fetched_blocks = Vec::new();

        let mut manifests_received = 0;
        let mut blocks_received = 0;
        let mut bytes_transferred = 0;

        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 50;

        while !to_fetch.is_empty() && iterations < MAX_ITERATIONS {
            iterations += 1;
            let delta = akshara_aadhaara::Delta::new(to_fetch.into_iter().collect());

            for addr in delta.missing() {
                fetched.insert(*addr);
            }

            let mut portions_stream = self.transport.request_portions(&delta).await?;

            let mut next_to_fetch = HashSet::new();

            use futures::StreamExt;
            while let Some(portion_result) = portions_stream.next().await {
                let portion = portion_result
                    .map_err(|e| Error::SyncFailed(format!("Portion stream error: {}", e)))?;

                let addr = portion.id();
                let bytes = portion.data();
                bytes_transferred += bytes.len() as u64;

                if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                    let manifest = akshara_aadhaara::from_canonical_bytes::<
                        akshara_aadhaara::Manifest,
                    >(bytes)
                    .map_err(|e| Error::SyncFailed(format!("Failed to parse manifest: {}", e)))?;

                    let actual_id = Address::from(manifest.id());
                    if actual_id != *addr {
                        return Err(Error::SyncFailed(format!(
                            "CID mismatch: expected {}, got {}",
                            addr, actual_id
                        )));
                    }

                    // Store manifest so we can resolve its path and walk the parents
                    store
                        .put_manifest(&manifest)
                        .await
                        .map_err(Error::Protocol)?;

                    // Add content root to queue if not fetched/stored
                    let root_addr = Address::from(manifest.content_root());
                    block_graph_ids.insert(root_addr, manifest.graph_id());
                    if root_addr != Address::null() && !fetched.contains(&root_addr) {
                        let root_bid = akshara_aadhaara::BlockId::try_from(root_addr).unwrap();
                        if store
                            .get_block(&root_bid)
                            .await
                            .map_err(Error::Protocol)?
                            .is_none()
                        {
                            next_to_fetch.insert(root_addr);
                        }
                    }

                    // Add identity anchor manifest to queue if not fetched/stored
                    let anchor_mid = manifest.identity_anchor();
                    if anchor_mid != akshara_aadhaara::ManifestId::null() {
                        let anchor_addr = Address::from(anchor_mid);
                        if !fetched.contains(&anchor_addr)
                            && store
                                .get_manifest(&anchor_mid)
                                .await
                                .map_err(Error::Protocol)?
                                .is_none()
                        {
                            next_to_fetch.insert(anchor_addr);
                        }
                    }

                    // Add parents to queue if not fetched/stored
                    for parent_mid in manifest.parents() {
                        let parent_addr = Address::from(*parent_mid);
                        if !fetched.contains(&parent_addr)
                            && store
                                .get_manifest(parent_mid)
                                .await
                                .map_err(Error::Protocol)?
                                .is_none()
                        {
                            next_to_fetch.insert(parent_addr);
                        }
                    }

                    fetched_manifests.push(manifest);
                    manifests_received += 1;
                } else {
                    let block =
                        akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(bytes)
                            .map_err(|e| {
                                Error::SyncFailed(format!("Failed to parse block: {}", e))
                            })?;

                    let actual_id = Address::from(block.id());
                    if actual_id != *addr {
                        return Err(Error::SyncFailed(format!(
                            "CID mismatch: expected {}, got {}",
                            addr, actual_id
                        )));
                    }

                    // Store block so we can decrypt/traverse it
                    store.put_block(&block).await.map_err(Error::Protocol)?;

                    let b_graph_id = block_graph_ids.get(addr).cloned().unwrap_or(graph_id);
                    let dec_key = if b_graph_id == graph_id {
                        key
                    } else {
                        &akshara_aadhaara::IDENTITY_GRAPH_KEY
                    };

                    // If it is an index block, decrypt and extract children
                    if *block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1
                        && let Ok(plaintext) = block.decrypt(&b_graph_id, dec_key)
                        && let Ok(index) = akshara_aadhaara::from_canonical_bytes::<
                            std::collections::BTreeMap<String, Address>,
                        >(&plaintext)
                    {
                        for (_, child_addr) in index {
                            if child_addr != Address::null() && !fetched.contains(&child_addr) {
                                block_graph_ids.insert(child_addr, b_graph_id);
                                if child_addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                                    let mid =
                                        akshara_aadhaara::ManifestId::try_from(child_addr).unwrap();
                                    if store
                                        .get_manifest(&mid)
                                        .await
                                        .map_err(Error::Protocol)?
                                        .is_none()
                                    {
                                        next_to_fetch.insert(child_addr);
                                    }
                                } else {
                                    let bid =
                                        akshara_aadhaara::BlockId::try_from(child_addr).unwrap();
                                    if store
                                        .get_block(&bid)
                                        .await
                                        .map_err(Error::Protocol)?
                                        .is_none()
                                    {
                                        next_to_fetch.insert(child_addr);
                                    }
                                }
                            }
                        }
                    }

                    // Add parents to queue if not fetched/stored
                    for parent_bid in block.parents() {
                        let parent_addr = Address::from(*parent_bid);
                        block_graph_ids.insert(parent_addr, b_graph_id);
                        if !fetched.contains(&parent_addr)
                            && store
                                .get_block(parent_bid)
                                .await
                                .map_err(Error::Protocol)?
                                .is_none()
                        {
                            next_to_fetch.insert(parent_addr);
                        }
                    }

                    fetched_blocks.push(block);
                    blocks_received += 1;
                }
            }

            to_fetch = next_to_fetch;
        }

        if iterations >= MAX_ITERATIONS {
            return Err(Error::SyncFailed(
                "Exceeded max pull sync iterations (potential cycle)".to_string(),
            ));
        }

        // 5. Converge: Audit all received blocks and manifests now that we have all blocks in the store
        let is_identity_sync = graph_id == self.vault.get_identity_id().await?;
        let latest_anchor = self.vault.latest_identity_anchor();

        let mut auditor = akshara_aadhaara::Auditor::new(store).with_graph_key(key.clone());
        if latest_anchor != akshara_aadhaara::ManifestId::null() {
            auditor = auditor.with_latest_identity(latest_anchor);
        }

        for block in &fetched_blocks {
            auditor.audit_block(block).map_err(Error::Protocol)?;
        }

        for manifest in &fetched_manifests {
            let expected_id = if manifest.graph_id() == graph_id {
                Some(&graph_id)
            } else {
                None
            };
            auditor
                .audit_manifest(manifest, expected_id)
                .await
                .map_err(Error::Protocol)?;
            if is_identity_sync {
                self.vault.update_identity_anchor(manifest.id());
            }
        }

        // 6. Push local surplus to peer
        let self_missing = comparison.self_surplus.missing().to_vec();
        if !self_missing.is_empty() {
            let self_missing_expanded = self
                .expand_delta_with_key(store, &graph_id, key, self_missing)
                .await?;
            let push_stream = self.stream_surplus(store, self_missing_expanded).await;

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

    /// Expands a delta of CIDs by decrypting and walking the Merkle Index Tree.
    /// This is necessary because in the blind model, the relay/store cannot look inside encrypted index blocks.
    #[allow(clippy::collapsible_if)]
    async fn expand_delta_with_key(
        &self,
        store: &InMemoryStore,
        graph_id: &GraphId,
        key: &akshara_aadhaara::GraphKey,
        addresses: Vec<Address>,
    ) -> Result<Vec<Address>> {
        use std::collections::{HashSet, VecDeque};
        let mut expanded = HashSet::new();
        let mut queue = VecDeque::new();

        for addr in addresses {
            if expanded.insert(addr) {
                if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                    let mid = akshara_aadhaara::ManifestId::try_from(addr).unwrap();
                    if let Ok(Some(manifest)) = store.get_manifest(&mid).await {
                        let root_id = manifest.content_root();
                        if expanded.insert(Address::from(root_id)) {
                            queue.push_back(root_id);
                        }
                    }
                } else if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_BLOCK {
                    let bid = akshara_aadhaara::BlockId::try_from(addr).unwrap();
                    queue.push_back(bid);
                }
            }
        }

        while let Some(current_id) = queue.pop_front() {
            if let Ok(Some(block)) = store.get_block(&current_id).await {
                if *block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1 {
                    if let Ok(plaintext) = block.decrypt(graph_id, key) {
                        if let Ok(index) = akshara_aadhaara::from_canonical_bytes::<
                            std::collections::BTreeMap<String, Address>,
                        >(&plaintext)
                        {
                            for (_, addr) in index {
                                if expanded.insert(addr) {
                                    if let Ok(bid) = akshara_aadhaara::BlockId::try_from(addr) {
                                        queue.push_back(bid);
                                    }
                                }
                            }
                        }
                    }
                }
                for parent in block.parents() {
                    if expanded.insert(Address::from(*parent)) {
                        queue.push_back(*parent);
                    }
                }
            }
        }

        Ok(expanded.into_iter().collect())
    }
}
