use crate::crypto::GraphKey;
use crate::error::{StoreError, SovereignError};
use crate::graph::{BlockId, ManifestId};
use crate::store::GraphStore;
use cid::Cid;
use std::collections::{HashSet, VecDeque, BTreeMap};

pub struct GraphWalker<'a, S: GraphStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> GraphWalker<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Resolves a human-readable path (e.g. "docs/title") into a CID.
    ///
    /// This method walks the Merkle Index Tree starting from the provided root.
    /// It requires the GraphKey to decrypt the structural index blocks.
    pub fn resolve_path(
        &self,
        root: BlockId,
        path: &str,
        key: &GraphKey,
    ) -> Result<Cid, SovereignError> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_cid = root.0;

        for segment in segments {
            // 1. Fetch the current block
            let block_id = BlockId(current_cid);
            let block = self.store.get_block(&block_id)?
                .ok_or_else(|| SovereignError::Store(StoreError::NotFound(format!("Block {}", block_id))))?;

            // 2. Decrypt and parse as Index
            // We use CBOR for indices.
            let plaintext = block.content().decrypt(key)?;
            let index: BTreeMap<String, Cid> = serde_cbor::from_slice(&plaintext)
                .map_err(|e| SovereignError::InternalError(format!("Path resolution failed: Block is not a valid index: {}", e)))?;

            // 3. Find the next segment
            current_cid = index.get(segment)
                .cloned()
                .ok_or_else(|| SovereignError::Store(StoreError::NotFound(format!("Path segment '{}' not found", segment))))?;
        }

        Ok(current_cid)
    }

    /// BFS to find all ancestors.
    pub fn get_ancestors(&self, start: &ManifestId) -> Result<HashSet<ManifestId>, SovereignError> {
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

        Ok(ancestors)
    }

    /// Finds the Lowest Common Ancestor (LCA) of two Manifests.
    pub fn find_lca(
        &self,
        a: &ManifestId,
        b: &ManifestId,
    ) -> Result<Option<ManifestId>, SovereignError> {
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

        Ok(None)
    }
}

pub struct BlockWalker<'a, S: GraphStore + ?Sized> {
    store: &'a S,
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