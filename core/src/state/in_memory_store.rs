use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, Lockbox};
use crate::base::error::{SovereignError, StoreError};
use crate::graph::{Block, Manifest};
use crate::state::store::{GraphStore, RecipientLockboxes};

/// A simple in-memory implementation of GraphStore for testing and temporary storage.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    blocks: Arc<RwLock<HashMap<BlockId, Block>>>,
    manifests: Arc<RwLock<HashMap<ManifestId, Manifest>>>,
    lockboxes: Arc<RwLock<HashMap<EncryptionPublicKey, RecipientLockboxes>>>,
    // Track current heads per graph
    heads: Arc<RwLock<HashMap<GraphId, HashSet<ManifestId>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GraphStore for InMemoryStore {
    fn put_block(&mut self, block: &Block) -> Result<(), SovereignError> {
        self.blocks
            .write()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?
            .insert(block.id(), block.clone());
        Ok(())
    }

    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError> {
        let blocks = self
            .blocks
            .read()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;
        Ok(blocks.get(id).cloned())
    }

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError> {
        let mut manifests = self
            .manifests
            .write()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;

        let mut heads_map = self
            .heads
            .write()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;

        let graph_id = manifest.graph_id();
        let m_id = manifest.id();

        // 1. Save manifest
        manifests.insert(m_id, manifest.clone());

        // 2. Update heads: New manifest is a potential head
        let doc_heads = heads_map.entry(graph_id).or_insert_with(HashSet::new);
        doc_heads.insert(m_id);

        // 3. Update heads: Its parents are no longer heads
        // FIXME: This logic assumes topological ordering (parents arrive before children).
        // If a child arrives before a parent, the parent will incorrectly remain a "head".
        // This is safe but inefficient for sync. Long-term fix: parent-of reverse index.
        for parent_id in manifest.parents() {
            doc_heads.remove(parent_id);
        }

        Ok(())
    }

    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError> {
        let manifests = self
            .manifests
            .read()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;
        Ok(manifests.get(id).cloned())
    }

    fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError> {
        let heads_map = self
            .heads
            .read()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;

        let result = heads_map
            .get(graph_id)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default();

        Ok(result)
    }

    fn put_lockbox(
        &mut self,
        graph_id: GraphId,
        recipient: &EncryptionPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError> {
        let mut lockboxes = self
            .lockboxes
            .write()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;
        let entry = lockboxes.entry(recipient.clone()).or_insert_with(Vec::new);

        entry.push((graph_id, lockbox.clone()));
        Ok(())
    }

    fn get_lockboxes_for_recipient(
        &self,
        recipient: &EncryptionPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|_| SovereignError::Store(StoreError::LockPoisoned))?;
        Ok(lockboxes.get(recipient).cloned().unwrap_or_default())
    }
}
