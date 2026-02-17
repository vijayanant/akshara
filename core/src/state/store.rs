use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::Lockbox;
use crate::base::crypto::SigningPublicKey;
use crate::base::error::SovereignError;
use crate::graph::{Block, Manifest};

pub trait GraphStore: Send + Sync {
    fn put_block(&mut self, block: &Block) -> Result<(), SovereignError>;
    fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError>;

    fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError>;
    fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError>;

    fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError>;

    fn put_lockbox(
        &mut self,
        graph_id: GraphId,
        recipient: &SigningPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError>;

    fn get_lockboxes_for_recipient(
        &self,
        recipient: &SigningPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError>;
}
