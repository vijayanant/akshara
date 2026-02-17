use crate::base::address::ManifestId;
use crate::base::error::SovereignError;
use crate::protocol::{SyncRequest, SyncResponse};
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use metrics::counter;
use std::collections::HashSet;
use tracing::{Level, debug, span, trace};

pub struct SyncEngine<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
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
        let span = span!(Level::INFO, "sync_calculate", graph_id = ?request.graph_id);
        let _enter = span.enter();

        let walker = GraphWalker::new(self.store);

        // 1. Calculate Local Known Set (What the Server Has)
        let mut local_known = HashSet::new();
        for head in local_heads {
            local_known.insert(*head);
            let ancestors = walker.get_ancestors(head)?;
            local_known.extend(ancestors);
        }
        trace!(
            local_count = local_known.len(),
            "Calculated local known set"
        );

        // 2. Calculate Remote Known Set (What the Client Has)
        let mut remote_known = HashSet::new();
        for head in request.heads() {
            if local_known.contains(head) {
                remote_known.insert(*head);
                let ancestors = walker.get_ancestors(head)?;
                remote_known.extend(ancestors);
            }
        }
        trace!(
            remote_count = remote_known.len(),
            "Calculated common ancestor set"
        );

        // 3. Diff Manifests
        let missing_manifests: Vec<ManifestId> =
            local_known.difference(&remote_known).cloned().collect();

        // 4. Missing Blocks
        let mut missing_blocks_set = HashSet::new();
        for m_id in &missing_manifests {
            if let Some(manifest) = self.store.get_manifest(m_id)? {
                missing_blocks_set.insert(manifest.content_root());
            }
        }

        // --- Log before Move ---
        debug!(
            manifests = missing_manifests.len(),
            blocks = missing_blocks_set.len(),
            "Sync calculation complete"
        );

        counter!("sovereign.sync.manifests_missing").increment(missing_manifests.len() as u64);
        counter!("sovereign.sync.blocks_missing").increment(missing_blocks_set.len() as u64);

        let missing_blocks = missing_blocks_set.into_iter().collect();

        Ok(SyncResponse::new(missing_manifests, missing_blocks))
    }
}
