use crate::crypto::{EncryptionPublicKey, Lockbox};
use crate::error::SovereignError;
use crate::graph::{Block, BlockId, DocId, Manifest, ManifestId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A generic interface for storing and retrieving graph objects.
pub trait GraphStore {
    fn put_block(&mut self, block: &Block) -> Result<(), SovereignError>;
    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError>;

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError>;
    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError>;

    // Lockbox Storage
    fn put_lockbox(
        &mut self,
        doc_id: DocId,
        recipient: &EncryptionPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError>;
    fn get_lockboxes_for_recipient(
        &self,
        recipient: &EncryptionPublicKey,
    ) -> Result<Vec<(DocId, Lockbox)>, SovereignError>;
}

type RecipientLockboxes = Vec<(DocId, Lockbox)>;

/// A simple in-memory implementation of GraphStore for testing and temporary storage.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    blocks: Arc<RwLock<HashMap<BlockId, Block>>>,
    manifests: Arc<RwLock<HashMap<ManifestId, Manifest>>>,
    // Map<RecipientKey, List<(DocId, Lockbox)>>
    lockboxes: Arc<RwLock<HashMap<EncryptionPublicKey, RecipientLockboxes>>>,
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
            .map_err(|e| SovereignError::InternalError(e.to_string()))?
            .insert(block.id(), block.clone());
        Ok(())
    }

    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        Ok(blocks.get(id).cloned())
    }

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError> {
        self.manifests
            .write()
            .map_err(|e| SovereignError::InternalError(e.to_string()))?
            .insert(manifest.id(), manifest.clone());
        Ok(())
    }

    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError> {
        let manifests = self
            .manifests
            .read()
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        Ok(manifests.get(id).cloned())
    }

    fn put_lockbox(
        &mut self,
        doc_id: DocId,
        recipient: &EncryptionPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError> {
        let mut lockboxes = self
            .lockboxes
            .write()
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        let entry = lockboxes.entry(recipient.clone()).or_insert_with(Vec::new);

        entry.push((doc_id, lockbox.clone()));
        Ok(())
    }

    fn get_lockboxes_for_recipient(
        &self,
        recipient: &EncryptionPublicKey,
    ) -> Result<Vec<(DocId, Lockbox)>, SovereignError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        Ok(lockboxes.get(recipient).cloned().unwrap_or_default())
    }
}
