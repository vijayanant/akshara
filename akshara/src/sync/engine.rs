//! Sync engine for orchestrating graph synchronization.
//!
//! The SyncEngine coordinates between the transport layer and the protocol layer
//! to synchronize graphs with relays or peers.

use crate::sync::Conflict;
use akshara_aadhaara::{
    Address, BlockId, GraphId, GraphStore, InMemoryStore, Portion, Reconciler, SyncMode,
};
use futures::stream::{self, Stream};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::graph::SyncReport;
use crate::sync::transport::SyncTransport;
use crate::vault::Vault;

/// Context for portion processing during pull sync.
struct IncomingContext<'a> {
    store: &'a InMemoryStore,
    fetched: &'a HashSet<Address>,
    block_graph_ids: &'a mut HashMap<Address, GraphId>,
    next_to_fetch: &'a mut HashSet<Address>,
}

impl<'a> IncomingContext<'a> {
    async fn queue_manifest_if_missing(
        &mut self,
        mid: &akshara_aadhaara::ManifestId,
    ) -> Result<()> {
        let addr = Address::from(*mid);
        if !self.fetched.contains(&addr)
            && self
                .store
                .get_manifest(mid)
                .await
                .map_err(Error::Protocol)?
                .is_none()
        {
            self.next_to_fetch.insert(addr);
        }
        Ok(())
    }

    async fn queue_block_if_missing(
        &mut self,
        bid: &akshara_aadhaara::BlockId,
        graph_id: GraphId,
    ) -> Result<()> {
        let addr = Address::from(*bid);
        self.block_graph_ids.insert(addr, graph_id);
        if !self.fetched.contains(&addr)
            && self
                .store
                .get_block(bid)
                .await
                .map_err(Error::Protocol)?
                .is_none()
        {
            self.next_to_fetch.insert(addr);
        }
        Ok(())
    }
}

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
    pub async fn sync_all(&self, _store: &InMemoryStore, _mode: SyncMode) -> Result<SyncReport> {
        // TODO: Iterate over all graphs in the registry and sync them.
        // For now, return empty report
        Ok(SyncReport {
            graphs_synced: 0,
            manifests_received: 0,
            blocks_received: 0,
            bytes_transferred: 0,
            conflicts_detected: 0,
            conflicts: vec![],
        })
    }

    /// Synchronize a single graph with the remote peer.
    pub async fn sync_graph(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
        key: &akshara_aadhaara::GraphKey,
        mode: SyncMode,
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
            .reconcile(&peer_heads, &local_heads, mode)
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
                conflicts: vec![],
            });
        }

        // 4. Request missing portions from remote, recursively discovering nested blocks via Merkle Tree index decryption
        let PullResult {
            manifests_received,
            blocks_received,
            bytes_transferred,
            fetched_manifests,
            fetched_blocks,
        } = self
            .pull_peer_portions(graph_id, store, key, &comparison.peer_surplus)
            .await?;

        // 5. Converge: Audit all received blocks and manifests now that we have all blocks in the store
        self.audit_fetched_data(graph_id, store, key, &fetched_manifests, &fetched_blocks)
            .await?;

        // 6. Push missing local portions to remote peer
        self.push_local_portions(graph_id, store, key, &comparison.self_surplus, mode)
            .await?;

        // 7. Conflict detection
        let conflicts = self.detect_conflicts(graph_id, store, key).await?;
        let conflicts_detected = conflicts.len();

        Ok(SyncReport {
            graphs_synced: 1,
            manifests_received,
            blocks_received,
            bytes_transferred,
            conflicts_detected,
            conflicts,
        })
    }

    /// Pull missing manifests and blocks from the remote peer, discovering nested structures.
    async fn pull_peer_portions(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
        key: &akshara_aadhaara::GraphKey,
        peer_surplus: &akshara_aadhaara::Delta,
    ) -> Result<PullResult> {
        use std::collections::{HashMap, HashSet};
        let mut fetched = HashSet::new();
        let mut to_fetch: HashSet<Address> = peer_surplus.missing().iter().cloned().collect();
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

                let mut ctx = IncomingContext {
                    store,
                    fetched: &fetched,
                    block_graph_ids: &mut block_graph_ids,
                    next_to_fetch: &mut next_to_fetch,
                };

                if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                    self.process_incoming_manifest(addr, bytes, &mut ctx, &mut fetched_manifests)
                        .await?;
                    manifests_received += 1;
                } else {
                    self.process_incoming_block(
                        graph_id,
                        key,
                        addr,
                        bytes,
                        &mut ctx,
                        &mut fetched_blocks,
                    )
                    .await?;
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

        Ok(PullResult {
            manifests_received,
            blocks_received,
            bytes_transferred,
            fetched_manifests,
            fetched_blocks,
        })
    }

    /// Process a manifest portion received during pull sync.
    async fn process_incoming_manifest(
        &self,
        addr: &Address,
        bytes: &[u8],
        ctx: &mut IncomingContext<'_>,
        fetched_manifests: &mut Vec<akshara_aadhaara::Manifest>,
    ) -> Result<()> {
        let manifest = akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Manifest>(bytes)
            .map_err(|e| Error::SyncFailed(format!("Failed to parse manifest: {}", e)))?;

        let actual_id = Address::from(manifest.id());
        if actual_id != *addr {
            return Err(Error::SyncFailed(format!(
                "CID mismatch: expected {}, got {}",
                addr, actual_id
            )));
        }

        ctx.store
            .put_manifest(&manifest)
            .await
            .map_err(Error::Protocol)?;

        let root_addr = Address::from(manifest.content_root());
        if root_addr != Address::null() {
            let root_bid =
                akshara_aadhaara::BlockId::try_from(root_addr).map_err(Error::Protocol)?;
            ctx.queue_block_if_missing(&root_bid, manifest.graph_id())
                .await?;
        }

        let anchor_mid = manifest.identity_anchor();
        if anchor_mid != akshara_aadhaara::ManifestId::null() {
            ctx.queue_manifest_if_missing(&anchor_mid).await?;
        }

        for parent_mid in manifest.parents() {
            ctx.queue_manifest_if_missing(parent_mid).await?;
        }

        fetched_manifests.push(manifest);
        Ok(())
    }

    /// Helper to process index block links and decrypt child portions.
    async fn process_index_block_links(
        &self,
        block: &akshara_aadhaara::Block,
        graph_id: GraphId,
        key: &akshara_aadhaara::GraphKey,
        ctx: &mut IncomingContext<'_>,
    ) -> Result<()> {
        let b_graph_id = ctx
            .block_graph_ids
            .get(&Address::from(block.id()))
            .cloned()
            .unwrap_or(graph_id);
        let dec_key = if b_graph_id == graph_id {
            key
        } else {
            &akshara_aadhaara::IDENTITY_GRAPH_KEY
        };

        if *block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1
            && let Ok(plaintext) = block.decrypt(&b_graph_id, dec_key)
            && let Ok(index) = akshara_aadhaara::from_canonical_bytes::<
                std::collections::BTreeMap<String, Address>,
            >(&plaintext)
        {
            for (_, child_addr) in index {
                if child_addr != Address::null() && !ctx.fetched.contains(&child_addr) {
                    ctx.block_graph_ids.insert(child_addr, b_graph_id);
                    if child_addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                        let mid = akshara_aadhaara::ManifestId::try_from(child_addr)
                            .map_err(Error::Protocol)?;
                        ctx.queue_manifest_if_missing(&mid).await?;
                    } else {
                        let bid = akshara_aadhaara::BlockId::try_from(child_addr)
                            .map_err(Error::Protocol)?;
                        ctx.queue_block_if_missing(&bid, b_graph_id).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Process a data or index block portion received during pull sync.
    async fn process_incoming_block(
        &self,
        graph_id: GraphId,
        key: &akshara_aadhaara::GraphKey,
        addr: &Address,
        bytes: &[u8],
        ctx: &mut IncomingContext<'_>,
        fetched_blocks: &mut Vec<akshara_aadhaara::Block>,
    ) -> Result<()> {
        let block = akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(bytes)
            .map_err(|e| Error::SyncFailed(format!("Failed to parse block: {}", e)))?;

        let actual_id = Address::from(block.id());
        if actual_id != *addr {
            return Err(Error::SyncFailed(format!(
                "CID mismatch: expected {}, got {}",
                addr, actual_id
            )));
        }

        ctx.store.put_block(&block).await.map_err(Error::Protocol)?;

        self.process_index_block_links(&block, graph_id, key, ctx)
            .await?;

        let b_graph_id = ctx.block_graph_ids.get(addr).cloned().unwrap_or(graph_id);
        for parent_bid in block.parents() {
            ctx.queue_block_if_missing(parent_bid, b_graph_id).await?;
        }

        fetched_blocks.push(block);
        Ok(())
    }

    /// Audit all fetched manifests and blocks to verify cryptographic integrity.
    async fn audit_fetched_data(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
        key: &akshara_aadhaara::GraphKey,
        fetched_manifests: &[akshara_aadhaara::Manifest],
        fetched_blocks: &[akshara_aadhaara::Block],
    ) -> Result<()> {
        let is_identity_sync = graph_id == self.vault.get_identity_id().await?;
        let latest_anchor = self.vault.latest_identity_anchor();

        let mut auditor = akshara_aadhaara::Auditor::new(store).with_graph_key(key.clone());
        if latest_anchor != akshara_aadhaara::ManifestId::null() {
            auditor = auditor.with_latest_identity(latest_anchor);
        }

        for block in fetched_blocks {
            auditor.audit_block(block).map_err(Error::Protocol)?;
        }

        for manifest in fetched_manifests {
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
        Ok(())
    }

    /// Push local missing manifests and blocks to the peer.
    async fn push_local_portions(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
        key: &akshara_aadhaara::GraphKey,
        self_surplus: &akshara_aadhaara::Delta,
        mode: SyncMode,
    ) -> Result<()> {
        let self_missing = self_surplus.missing().to_vec();
        if !self_missing.is_empty() {
            let self_missing_expanded = self
                .expand_delta_with_key(store, &graph_id, key, self_missing, mode)
                .await?;
            let push_stream = self.stream_surplus(store, self_missing_expanded).await;

            // We need to track how many bytes we are pushing
            // For now, we'll just send the stream and assume success
            self.transport.push_portions(push_stream).await?;

            // TODO: Accurate bytes_transferred update for push
        }
        Ok(())
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
                match akshara_aadhaara::ManifestId::try_from(addr) {
                    Ok(mid) => match store.get_manifest(&mid).await {
                        Ok(Some(m)) => akshara_aadhaara::to_canonical_bytes(&m)
                            .map(|bytes| Portion::new(addr, bytes))
                            .map_err(Error::Protocol),
                        Ok(None) => Err(Error::Internal(format!(
                            "Manifest {} missing during push",
                            mid
                        ))),
                        Err(e) => Err(Error::Protocol(e)),
                    },
                    Err(e) => Err(Error::Protocol(e)),
                }
            } else {
                match akshara_aadhaara::BlockId::try_from(addr) {
                    Ok(bid) => match store.get_block(&bid).await {
                        Ok(Some(b)) => akshara_aadhaara::to_canonical_bytes(&b)
                            .map(|bytes| Portion::new(addr, bytes))
                            .map_err(Error::Protocol),
                        Ok(None) => Err(Error::Internal(format!(
                            "Block {} missing during push",
                            bid
                        ))),
                        Err(e) => Err(Error::Protocol(e)),
                    },
                    Err(e) => Err(Error::Protocol(e)),
                }
            };

            Some((res, (store, missing)))
        });

        Box::pin(s)
    }

    async fn expand_delta_with_key(
        &self,
        store: &InMemoryStore,
        graph_id: &GraphId,
        key: &akshara_aadhaara::GraphKey,
        addresses: Vec<Address>,
        mode: SyncMode,
    ) -> Result<Vec<Address>> {
        use std::collections::{HashSet, VecDeque};
        let mut expanded = HashSet::new();
        let mut queue = VecDeque::new();

        for addr in addresses {
            if expanded.insert(addr) {
                if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                    let mid =
                        akshara_aadhaara::ManifestId::try_from(addr).map_err(Error::Protocol)?;
                    if let Ok(Some(manifest)) = store.get_manifest(&mid).await {
                        let root_id = manifest.content_root();
                        if expanded.insert(Address::from(root_id)) {
                            queue.push_back(root_id);
                        }
                    }
                } else if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_BLOCK {
                    let bid = akshara_aadhaara::BlockId::try_from(addr).map_err(Error::Protocol)?;
                    queue.push_back(bid);
                }
            }
        }

        while let Some(current_id) = queue.pop_front() {
            if let Ok(Some(block)) = store.get_block(&current_id).await {
                if *block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1
                    && let Ok(plaintext) = block.decrypt(graph_id, key)
                    && let Ok(index) = akshara_aadhaara::from_canonical_bytes::<
                        std::collections::BTreeMap<String, Address>,
                    >(&plaintext)
                {
                    for (_, addr) in index {
                        if expanded.insert(addr)
                            && let Ok(bid) = akshara_aadhaara::BlockId::try_from(addr)
                        {
                            queue.push_back(bid);
                        }
                    }
                }
                if mode == SyncMode::Full {
                    for parent in block.parents() {
                        if expanded.insert(Address::from(*parent)) {
                            queue.push_back(*parent);
                        }
                    }
                }
            }
        }

        Ok(expanded.into_iter().collect())
    }

    /// Detect path-level conflicts across concurrent heads of a graph.
    /// Helper to flatten a manifest head index.
    async fn flatten_head(
        store: &InMemoryStore,
        graph_id: &GraphId,
        key: &akshara_aadhaara::GraphKey,
        head: &akshara_aadhaara::ManifestId,
    ) -> Result<Option<BTreeMap<String, Address>>> {
        if let Some(manifest) = store.get_manifest(head).await.map_err(Error::Protocol)? {
            let root = manifest.content_root();
            if root != akshara_aadhaara::BlockId::null() {
                let mut flattened = BTreeMap::new();
                flatten_index_rec(store, graph_id, &root, "".to_string(), key, &mut flattened)
                    .await?;
                return Ok(Some(flattened));
            }
        }
        Ok(None)
    }

    pub async fn detect_conflicts(
        &self,
        graph_id: GraphId,
        store: &InMemoryStore,
        key: &akshara_aadhaara::GraphKey,
    ) -> Result<Vec<Conflict>> {
        let heads = store
            .get_heads(&graph_id)
            .await
            .map_err(|e| Error::SyncFailed(format!("Failed to get local heads: {}", e)))?;

        if heads.len() <= 1 {
            return Ok(vec![]);
        }

        let mut all_paths = HashSet::new();
        let mut head_flattened = HashMap::new();

        for head in &heads {
            if let Some(flattened) = Self::flatten_head(store, &graph_id, key, head).await? {
                all_paths.extend(flattened.keys().cloned());
                head_flattened.insert(*head, flattened);
            }
        }

        let mut conflicts = Vec::new();
        for path in all_paths {
            let mut distinct_targets = HashSet::new();
            let mut conflicting_heads = Vec::new();
            let mut divergent_blocks = Vec::new();

            for head in &heads {
                let bid_opt = head_flattened
                    .get(head)
                    .and_then(|f| f.get(&path))
                    .and_then(|addr| BlockId::try_from(*addr).ok());
                distinct_targets.insert(bid_opt);
                conflicting_heads.push(*head);
                if let Some(bid) = bid_opt {
                    divergent_blocks.push(bid);
                }
            }

            if distinct_targets.len() > 1 {
                conflicts.push(Conflict {
                    graph_id,
                    path,
                    heads: conflicting_heads,
                    divergent_blocks,
                    strategy: None,
                });
            }
        }

        Ok(conflicts)
    }
}

/// Recursive helper to flatten a Merkle Index starting from root.
fn flatten_index_rec<'a>(
    store: &'a InMemoryStore,
    graph_id: &'a GraphId,
    block_id: &'a akshara_aadhaara::BlockId,
    current_path: String,
    key: &'a akshara_aadhaara::GraphKey,
    result: &'a mut std::collections::BTreeMap<String, Address>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let block = store
            .get_block(block_id)
            .await
            .map_err(Error::Protocol)?
            .ok_or_else(|| Error::SyncFailed(format!("Index block {} not found", block_id)))?;

        let plaintext = block
            .decrypt(graph_id, key)
            .map_err(|e| Error::SyncFailed(format!("Failed to decrypt index block: {}", e)))?;

        let index_map: std::collections::BTreeMap<String, Address> =
            akshara_aadhaara::from_canonical_bytes(&plaintext)
                .map_err(|e| Error::SyncFailed(format!("Failed to parse index: {}", e)))?;

        for (name, addr) in index_map {
            let path = format!("{}/{}", current_path, name);
            if addr.codec() == akshara_aadhaara::CODEC_AKSHARA_BLOCK {
                let child_id = akshara_aadhaara::BlockId::try_from(addr)
                    .map_err(|e| Error::SyncFailed(format!("Invalid block address: {}", e)))?;

                let child_block = store
                    .get_block(&child_id)
                    .await
                    .map_err(Error::Protocol)?
                    .ok_or_else(|| {
                        Error::SyncFailed(format!("Child block {} not found", child_id))
                    })?;

                if *child_block.block_type() == akshara_aadhaara::BlockType::AksharaIndexV1 {
                    flatten_index_rec(store, graph_id, &child_id, path, key, result).await?;
                } else {
                    result.insert(path, addr);
                }
            } else {
                result.insert(path, addr);
            }
        }
        Ok(())
    })
}

struct PullResult {
    manifests_received: usize,
    blocks_received: usize,
    bytes_transferred: u64,
    fetched_manifests: Vec<akshara_aadhaara::Manifest>,
    fetched_blocks: Vec<akshara_aadhaara::Block>,
}
