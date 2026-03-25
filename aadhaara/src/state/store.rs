use crate::base::address::{BlockId, GraphId, Lakshana, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, Lockbox, SigningPublicKey};
use crate::base::error::AksharaError;
use crate::graph::{Block, Manifest};
use crate::identity::types::PreKeyBundle;
use async_trait::async_trait;

#[async_trait]
pub trait GraphStore: Send + Sync {
    async fn put_block(&self, block: &Block) -> Result<(), AksharaError>;
    async fn get_block(&self, id: &BlockId) -> Result<Option<Block>, AksharaError>;

    async fn put_manifest(&self, manifest: &Manifest) -> Result<(), AksharaError>;
    async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, AksharaError>;

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError>;

    async fn put_lockbox(&self, lakshana: Lakshana, lockbox: &Lockbox) -> Result<(), AksharaError>;

    async fn get_lockboxes(&self, lakshana: &Lakshana) -> Result<Vec<Lockbox>, AksharaError>;

    /// Stores a Pre-Key Bundle for a specific device.
    async fn put_prekey_bundle(&self, bundle: &PreKeyBundle) -> Result<(), AksharaError>;

    /// Retrieves the current Pre-Key Bundle for a specific device.
    async fn get_prekey_bundle(
        &self,
        device_key: &SigningPublicKey,
    ) -> Result<Option<PreKeyBundle>, AksharaError>;

    /// Atomically retrieves and REMOVES a specific pre-key from a bundle.
    async fn consume_prekey(
        &self,
        device_key: &SigningPublicKey,
        prekey_index: u32,
    ) -> Result<Option<EncryptionPublicKey>, AksharaError>;
}
