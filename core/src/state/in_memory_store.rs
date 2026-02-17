use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{Lockbox, SigningPublicKey};
use crate::base::error::{SovereignError, StoreError};
use crate::graph::{Block, Manifest};
use crate::state::store::GraphStore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type LockboxMap = HashMap<SigningPublicKey, Vec<(GraphId, Lockbox)>>;

#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    pub(crate) blocks: Arc<RwLock<HashMap<BlockId, Block>>>,
    pub(crate) manifests: Arc<RwLock<HashMap<ManifestId, Manifest>>>,
    pub(crate) heads: Arc<RwLock<HashMap<GraphId, Vec<ManifestId>>>>,
    pub(crate) lockboxes: Arc<RwLock<LockboxMap>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GraphStore for InMemoryStore {
    fn put_block(&mut self, block: &Block) -> Result<(), SovereignError> {
        let mut blocks = self.blocks.write().map_err(|_| StoreError::LockPoisoned)?;
        blocks.insert(block.id(), block.clone());
        Ok(())
    }

    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError> {
        let blocks = self.blocks.read().map_err(|_| StoreError::LockPoisoned)?;
        Ok(blocks.get(id).cloned())
    }

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError> {
        // 1. Save content
        {
            let mut manifests = self
                .manifests
                .write()
                .map_err(|_| StoreError::LockPoisoned)?;
            manifests.insert(manifest.id(), manifest.clone());
        }

        // 2. Update Heads
        let mut heads_map = self.heads.write().map_err(|_| StoreError::LockPoisoned)?;
        let graph_heads = heads_map.entry(manifest.graph_id()).or_default();

        // If this manifest replaces parents, remove those parents from heads
        for parent in manifest.parents() {
            graph_heads.retain(|h| h != parent);
        }

        // Add this manifest as a new head
        if !graph_heads.contains(&manifest.id()) {
            graph_heads.push(manifest.id());
        }

        Ok(())
    }

    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError> {
        let manifests = self
            .manifests
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(manifests.get(id).cloned())
    }

    fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError> {
        let heads_map = self.heads.read().map_err(|_| StoreError::LockPoisoned)?;
        Ok(heads_map.get(graph_id).cloned().unwrap_or_default())
    }

    fn put_lockbox(
        &mut self,
        graph_id: GraphId,
        recipient: &SigningPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError> {
        let mut lockboxes = self
            .lockboxes
            .write()
            .map_err(|_| StoreError::LockPoisoned)?;
        let entries = lockboxes.entry(recipient.clone()).or_default();
        entries.push((graph_id, lockbox.clone()));
        Ok(())
    }

    fn get_lockboxes_for_recipient(
        &self,
        recipient: &SigningPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(lockboxes.get(recipient).cloned().unwrap_or_default())
    }
}
