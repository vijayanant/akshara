use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, Lockbox};
use crate::base::error::SovereignError;
use crate::graph::{Block, Manifest};

/// A generic interface for storing and retrieving graph objects.
pub trait GraphStore {
    fn put_block(&mut self, block: &Block) -> Result<(), SovereignError>;
    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError>;

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError>;
    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError>;

    /// Returns the current heads (unreferenced leaf manifests) for a given graph.
    fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError>;

    // Lockbox Storage
    fn put_lockbox(
        &mut self,
        graph_id: GraphId,
        recipient: &EncryptionPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError>;
    fn get_lockboxes_for_recipient(
        &self,
        recipient: &EncryptionPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError>;
}

pub(crate) type RecipientLockboxes = Vec<(GraphId, Lockbox)>;
