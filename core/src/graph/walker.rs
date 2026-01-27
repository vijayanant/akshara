use crate::error::SovereignError;
use crate::graph::{BlockId, ManifestId};
use crate::store::GraphStore;
use std::collections::{HashSet, VecDeque};

pub struct GraphWalker<'a, S: GraphStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> GraphWalker<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// BFS to find all ancestors.
    /// Returns a Set of IDs.
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
    /// Returns the first common ancestor found by walking back from `b`.
    pub fn find_lca(
        &self,
        a: &ManifestId,
        b: &ManifestId,
    ) -> Result<Option<ManifestId>, SovereignError> {
        if a == b {
            return Ok(Some(*a));
        }

        // 1. Get all ancestors of A (inclusive of A itself)
        let mut ancestors_a = self.get_ancestors(a)?;
        ancestors_a.insert(*a);

        // 2. Walk back from B
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

    // TODO: OPTIMISATION: This LCA algorithm involves two graph traversals.
    // For very large graphs, a more efficient algorithm could involve a simultaneous
    // traversal from both 'a' and 'b' to find the common ancestor faster.
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
