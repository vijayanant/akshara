use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::Lockbox;
use crate::base::crypto::SigningPublicKey;
use crate::base::error::SovereignError;
use crate::graph::{Block, Manifest};
use async_trait::async_trait;

#[async_trait]
pub trait GraphStore: Send + Sync {
    async fn put_block(&mut self, block: &Block) -> Result<(), SovereignError>;
    async fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError>;

    async fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError>;
    async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError>;

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError>;

    async fn put_lockbox(
        &mut self,
        graph_id: GraphId,
        recipient: &SigningPublicKey,
        lockbox: &Lockbox,
    ) -> Result<(), SovereignError>;

    async fn get_lockboxes_for_recipient(
        &self,
        recipient: &SigningPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError>;
}
