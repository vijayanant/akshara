use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, Lockbox, SigningPublicKey};
use crate::base::error::{SovereignError, StoreError};
use crate::graph::{Block, Manifest};
use crate::identity::types::PreKeyBundle;
use crate::state::store::GraphStore;
use async_trait::async_trait;
use metrics::counter;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

type LockboxMap = HashMap<SigningPublicKey, Vec<(GraphId, Lockbox)>>;
type PreKeyMap = HashMap<SigningPublicKey, PreKeyBundle>;

#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    pub(crate) blocks: Arc<RwLock<HashMap<BlockId, Block>>>,
    pub(crate) manifests: Arc<RwLock<HashMap<ManifestId, Manifest>>>,
    pub(crate) heads: Arc<RwLock<HashMap<GraphId, Vec<ManifestId>>>>,
    pub(crate) lockboxes: Arc<RwLock<LockboxMap>>,
    pub(crate) prekeys: Arc<RwLock<PreKeyMap>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GraphStore for InMemoryStore {
    async fn put_block(&mut self, block: &Block) -> Result<(), SovereignError> {
        let mut blocks = self.blocks.write().map_err(|_| StoreError::LockPoisoned)?;
        debug!(id = ?block.id(), "Storing block");
        blocks.insert(block.id(), block.clone());
        counter!("sovereign.store.put", "type" => "block").increment(1);
        Ok(())
    }

    async fn get_block(&self, id: &BlockId) -> Result<Option<Block>, SovereignError> {
        let blocks = self.blocks.read().map_err(|_| StoreError::LockPoisoned)?;
        let result = blocks.get(id).cloned();
        if result.is_some() {
            trace!(id = ?id, "Block found");
            counter!("sovereign.store.get", "type" => "block", "result" => "hit").increment(1);
        } else {
            counter!("sovereign.store.get", "type" => "block", "result" => "miss").increment(1);
        }
        Ok(result)
    }

    async fn put_manifest(&mut self, manifest: &Manifest) -> Result<(), SovereignError> {
        debug!(id = ?manifest.id(), graph_id = ?manifest.graph_id(), "Storing manifest");

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

        counter!("sovereign.store.put", "type" => "manifest").increment(1);
        Ok(())
    }

    async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, SovereignError> {
        let manifests = self
            .manifests
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        let result = manifests.get(id).cloned();
        if result.is_some() {
            counter!("sovereign.store.get", "type" => "manifest", "result" => "hit").increment(1);
        } else {
            counter!("sovereign.store.get", "type" => "manifest", "result" => "miss").increment(1);
        }
        Ok(result)
    }

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, SovereignError> {
        let heads_map = self.heads.read().map_err(|_| StoreError::LockPoisoned)?;
        let heads = heads_map.get(graph_id).cloned().unwrap_or_default();
        trace!(graph_id = ?graph_id, count = heads.len(), "Retrieved heads");
        Ok(heads)
    }

    async fn put_lockbox(
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
        counter!("sovereign.store.put", "type" => "lockbox").increment(1);
        Ok(())
    }

    async fn get_lockboxes_for_recipient(
        &self,
        recipient: &SigningPublicKey,
    ) -> Result<Vec<(GraphId, Lockbox)>, SovereignError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|_| StoreError::LockPoisoned)?;
        let entries = lockboxes.get(recipient).cloned().unwrap_or_default();
        counter!("sovereign.store.get", "type" => "lockbox").increment(1);
        Ok(entries)
    }

    async fn put_prekey_bundle(&mut self, bundle: &PreKeyBundle) -> Result<(), SovereignError> {
        let mut prekeys = self.prekeys.write().map_err(|_| StoreError::LockPoisoned)?;
        let device_key = bundle.device_identity.signing_key().clone();
        debug!(device = ?device_key, count = bundle.pre_keys.len(), "Storing pre-key bundle");
        prekeys.insert(device_key, bundle.clone());
        counter!("sovereign.store.put", "type" => "prekey_bundle").increment(1);
        Ok(())
    }

    async fn get_prekey_bundle(
        &self,
        device_key: &SigningPublicKey,
    ) -> Result<Option<PreKeyBundle>, SovereignError> {
        let prekeys = self.prekeys.read().map_err(|_| StoreError::LockPoisoned)?;
        let result = prekeys.get(device_key).cloned();
        counter!("sovereign.store.get", "type" => "prekey_bundle").increment(1);
        Ok(result)
    }

    async fn consume_prekey(
        &mut self,
        device_key: &SigningPublicKey,
        prekey_index: u32,
    ) -> Result<Option<EncryptionPublicKey>, SovereignError> {
        let mut prekeys = self.prekeys.write().map_err(|_| StoreError::LockPoisoned)?;

        if let Some(bundle) = prekeys.get_mut(device_key) {
            // THE ATOMIC CONSUMPTION: Remove from BTreeMap
            let key = bundle.pre_keys.remove(&prekey_index);

            if key.is_some() {
                debug!(device = ?device_key, index = prekey_index, "Consumed one-time pre-key");
                counter!("sovereign.store.consume", "type" => "prekey").increment(1);

                // AKSHARA RITUAL: After consuming, we should ideally re-sign the bundle
                // but since the Relay doesn't have the private key, we just track the depletion.
            }
            Ok(key)
        } else {
            Ok(None)
        }
    }
}
