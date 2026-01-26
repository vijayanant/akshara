use crate::error::SovereignError;
use crate::graph::ManifestId;
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

        // We start by expanding 'start', but we don't include it in 'ancestors'.
        // To do this, we manually expand 'start' first.

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
}
