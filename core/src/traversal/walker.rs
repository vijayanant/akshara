use crate::base::address::{BlockId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::base::error::{IntegrityError, SovereignError, StoreError};
use crate::state::store::GraphStore;
use cid::Cid;
use metrics::{counter, histogram};
use std::collections::{BTreeMap, HashSet, VecDeque};
use tracing::{Level, debug, span, trace};

/// `GraphWalker` provides high-level navigation across the Sovereign Merkle Index.
pub struct GraphWalker<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> GraphWalker<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Resolves a human-readable path sequence into a CID.
    ///
    /// This method walks the Merkle Index Tree starting from the provided root.
    /// It requires the GraphKey to decrypt the structural index blocks.
    ///
    /// # Security Invariants
    ///
    /// 1. **Cycle Detection:** We maintain a `visited` set of CIDs. A valid graph traversal
    ///    must never encounter the same CID twice. If it does, the graph is considered
    ///    malicious or malformed, and resolution fails immediately.
    ///
    /// 2. **Depth Limit (256):** We cap resolution at 256 segments. This is a "Defense in Depth"
    ///    measure to prevent stack overflow or CPU exhaustion attacks from excessively deep trees.
    ///
    /// 3. **Satyata Check (Existence):** We verify that the final resolved CID actually
    ///    exists in the local store. We do not resolve "Ghost Pointers."
    pub fn resolve_path(
        &self,
        root: BlockId,
        path: &str,
        key: &GraphKey,
    ) -> Result<Cid, SovereignError> {
        let span = span!(Level::DEBUG, "resolve_path", path = %path, root = ?root);
        let _enter = span.enter();

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if segments.len() > 256 {
            debug!("Path resolution failed: Depth limit exceeded");
            counter!("sovereign.walker.error", "reason" => "depth_limit").increment(1);
            return Err(SovereignError::InternalError(format!(
                "Path resolution depth limit exceeded (max: {})",
                256
            )));
        }

        let mut current_cid = *root.as_cid();
        let mut visited = HashSet::new();
        visited.insert(current_cid);

        let start_time = std::time::Instant::now();

        for segment in segments {
            let step_span =
                span!(Level::TRACE, "resolve_segment", segment = %segment, current = ?current_cid);
            let _step_enter = step_span.enter();

            // 1. Fetch the current block
            let block_id = BlockId::from_cid(current_cid);
            let block = self.store.get_block(&block_id)?.ok_or_else(|| {
                debug!(block_id = ?block_id, "Block not found during resolution");
                SovereignError::Store(StoreError::NotFound(format!("Block {}", block_id)))
            })?;

            // 2. Decrypt and parse as Index
            let plaintext = block.content().decrypt(key)?;
            let index: BTreeMap<String, Cid> = serde_cbor::from_slice(&plaintext).map_err(|e| {
                debug!(error = %e, "Block content is not a valid index");
                SovereignError::InternalError(format!(
                    "Path resolution failed: Block is not a valid index: {}",
                    e
                ))
            })?;

            // 3. Find the next segment
            current_cid = index.get(segment).cloned().ok_or_else(|| {
                trace!(segment = %segment, "Segment not found in index");
                SovereignError::Store(StoreError::NotFound(format!(
                    "Path segment '{}' not found",
                    segment
                )))
            })?;

            // 4. CYCLE DETECTION: Prevents infinite resolution loops.
            if !visited.insert(current_cid) {
                debug!(cid = ?current_cid, "Cycle detected in graph traversal");
                counter!("sovereign.walker.error", "reason" => "cycle_detected").increment(1);
                return Err(SovereignError::Integrity(IntegrityError::MalformedId));
            }
        }

        // 5. SATYATA CHECK: Ensure the target actually exists
        let final_id = BlockId::from_cid(current_cid);
        if self.store.get_block(&final_id)?.is_none() {
            debug!(final_id = ?final_id, "Resolved leaf missing from store");
            counter!("sovereign.walker.error", "reason" => "ghost_leaf").increment(1);
            return Err(SovereignError::Store(StoreError::NotFound(format!(
                "Resolved leaf block {} missing from store",
                final_id
            ))));
        }

        let elapsed = start_time.elapsed();
        histogram!("sovereign.walker.resolve_latency").record(elapsed);
        counter!("sovereign.walker.resolve_success").increment(1);

        Ok(current_cid)
    }

    /// BFS to find all ancestors of a manifest.
    pub fn get_ancestors(&self, start: &ManifestId) -> Result<HashSet<ManifestId>, SovereignError> {
        let span = span!(Level::DEBUG, "get_ancestors", start = ?start);
        let _enter = span.enter();

        let mut ancestors = HashSet::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        if let Some(manifest) = self.store.get_manifest(start)? {
            for parent in manifest.parents() {
                if !visited.contains(parent) {
                    visited.insert(*parent);
                    queue.push_back(*parent);
                    ancestors.insert(*parent);
                }
            }
        }

        while let Some(current_id) = queue.pop_front() {
            if let Some(manifest) = self.store.get_manifest(&current_id)? {
                for parent in manifest.parents() {
                    if !visited.contains(parent) {
                        visited.insert(*parent);
                        ancestors.insert(*parent);
                        queue.push_back(*parent);
                    }
                }
            }
        }

        trace!(count = ancestors.len(), "Ancestors found");
        Ok(ancestors)
    }

    /// Finds the Lowest Common Ancestor (LCA) of two Manifests.
    ///
    /// This is used to identify the "Split Point" where two forks of a graph diverged,
    /// which is the first step in performing a semantic merge.
    pub fn find_lca(
        &self,
        a: &ManifestId,
        b: &ManifestId,
    ) -> Result<Option<ManifestId>, SovereignError> {
        let span = span!(Level::DEBUG, "find_lca", a = ?a, b = ?b);
        let _enter = span.enter();

        if a == b {
            return Ok(Some(*a));
        }

        let mut ancestors_a = self.get_ancestors(a)?;
        ancestors_a.insert(*a);

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(*b);
        visited.insert(*b);

        while let Some(current_id) = queue.pop_front() {
            if ancestors_a.contains(&current_id) {
                trace!(lca = ?current_id, "LCA found");
                return Ok(Some(current_id));
            }

            if let Some(manifest) = self.store.get_manifest(&current_id)? {
                for parent in manifest.parents() {
                    if !visited.contains(parent) {
                        visited.insert(*parent);
                        queue.push_back(*parent);
                    }
                }
            }
        }

        debug!("No common ancestor found");
        Ok(None)
    }
}

pub struct BlockWalker<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> BlockWalker<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    pub fn is_ancestor(
        &self,
        descendant: &BlockId,
        ancestor: &BlockId,
    ) -> Result<bool, SovereignError> {
        let span = span!(Level::DEBUG, "block_is_ancestor", descendant = ?descendant, ancestor = ?ancestor);
        let _enter = span.enter();

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(*descendant);
        visited.insert(*descendant);

        while let Some(current_id) = queue.pop_front() {
            if current_id == *ancestor && current_id != *descendant {
                return Ok(true);
            }

            if let Some(block) = self.store.get_block(&current_id)? {
                for parent in block.parents() {
                    if !visited.contains(parent) {
                        visited.insert(*parent);
                        queue.push_back(*parent);
                    }
                }
            }
        }

        Ok(false)
    }
}
