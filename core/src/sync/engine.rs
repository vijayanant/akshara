use crate::error::SovereignError;
use crate::graph::{GraphWalker, ManifestId};
use crate::store::GraphStore;
use crate::sync::{SyncRequest, SyncResponse};
use std::collections::HashSet;

pub struct SyncEngine<'a, S: GraphStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> SyncEngine<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    pub fn calculate_response(
        &self,
        request: &SyncRequest,
        local_heads: &[ManifestId],
    ) -> Result<SyncResponse, SovereignError> {
        let walker = GraphWalker::new(self.store);

        // 1. Calculate Local Known Set (What the Server Has)
        // We do this first because it might be smaller or we might use it to prune remote check.
        let mut local_known = HashSet::new();
        for head in local_heads {
            local_known.insert(*head);
            let ancestors = walker.get_ancestors(head)?;
            local_known.extend(ancestors);
        }

        // 2. Calculate Remote Known Set (What the Client Has)
        // Optimization: If a remote head is NOT in local_known, we (Server) don't know about it.
        // We can ignore it (or error?). Standard sync logic usually ignores unknown remote heads
        // as "future" or "irrelevant to pull".
        let mut remote_known = HashSet::new();
        for head in request.heads() {
            // Only traverse if we actually have this head.
            if local_known.contains(head) {
                remote_known.insert(*head);
                let ancestors = walker.get_ancestors(head)?;
                remote_known.extend(ancestors);
            } else {
                // If we don't have the head, we assume we can't help them with that branch.
                // (In a Push scenario, we'd accept it, but this is Pull/Calc Response).
            }
        }

        // 3. Diff: Missing = Local - Remote
        let missing_manifests: Vec<ManifestId> =
            local_known.difference(&remote_known).cloned().collect();

        // 4. Missing Blocks
        // Optimization: Use a Set to deduplicate block IDs across multiple manifests.
        let mut missing_blocks_set = HashSet::new();
        for m_id in &missing_manifests {
            if let Some(manifest) = self.store.get_manifest(m_id)? {
                missing_blocks_set.extend(manifest.active_blocks().iter().cloned());
            }
        }

        let missing_blocks = missing_blocks_set.into_iter().collect();

        Ok(SyncResponse::new(missing_manifests, missing_blocks))
    }
}
