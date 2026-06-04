use crate::base::address::{BlockId, GraphId, Lakshana, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, SigningPublicKey};
use crate::base::error::{AksharaError, StoreError};

use crate::identity::types::PreKeyBundle;
use crate::state::store::GraphStore;
use async_trait::async_trait;
use metrics::counter;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

type LockboxMap = HashMap<Lakshana, Vec<Vec<u8>>>;
type PreKeyMap = HashMap<SigningPublicKey, Vec<u8>>;

#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    pub(crate) blocks: Arc<RwLock<HashMap<BlockId, Vec<u8>>>>,
    pub(crate) manifests: Arc<RwLock<HashMap<ManifestId, Vec<u8>>>>,
    pub(crate) heads: Arc<RwLock<HashMap<GraphId, Vec<ManifestId>>>>,
    pub(crate) lockboxes: Arc<RwLock<LockboxMap>>,
    pub(crate) prekeys: Arc<RwLock<PreKeyMap>>,
}

/// The maximum number of concurrent heads allowed per graph to prevent "Head Explosion" DoS attacks.
const MAX_HEADS: usize = 50;

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GraphStore for InMemoryStore {
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError> {
        let mut blocks = self
            .blocks
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        debug!(id = ?id, "Storing block bytes");
        blocks.insert(id.clone(), data.to_vec());
        counter!("akshara.store.put", "type" => "block").increment(1);
        Ok(())
    }

    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError> {
        let blocks = self
            .blocks
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let result = blocks.get(id).cloned();
        if result.is_some() {
            trace!(id = ?id, "Block bytes found");
            counter!("akshara.store.get", "type" => "block", "result" => "hit").increment(1);
        } else {
            counter!("akshara.store.get", "type" => "block", "result" => "miss").increment(1);
        }
        Ok(result)
    }

    async fn put_manifest_bytes(
        &self,
        id: &ManifestId,
        graph_id: &GraphId,
        parents: &[ManifestId],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        debug!(id = ?id, graph_id = ?graph_id, "Storing manifest bytes");

        // 1. Save content
        {
            let mut manifests = self
                .manifests
                .write()
                .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
            manifests.insert(id.clone(), data.to_vec());
        }

        // 2. Update Heads
        let mut heads_map = self
            .heads
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let graph_heads = heads_map.entry(graph_id.clone()).or_default();

        // If this manifest replaces parents, remove those parents from heads
        for parent in parents {
            graph_heads.retain(|h| h != parent);
        }

        // Add this manifest as a new head
        if !graph_heads.contains(id) {
            graph_heads.push(id.clone());
        }

        // ENFORCE FRONTIER CAP: Prevent "Head Explosion" DoS
        if graph_heads.len() > MAX_HEADS {
            return Err(AksharaError::TooManyHeads(MAX_HEADS));
        }

        counter!("akshara.store.put", "type" => "manifest").increment(1);
        Ok(())
    }

    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError> {
        let manifests = self
            .manifests
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let result = manifests.get(id).cloned();
        if result.is_some() {
            counter!("akshara.store.get", "type" => "manifest", "result" => "hit").increment(1);
        } else {
            counter!("akshara.store.get", "type" => "manifest", "result" => "miss").increment(1);
        }
        Ok(result)
    }

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError> {
        let heads_map = self
            .heads
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let heads = heads_map.get(graph_id).cloned().unwrap_or_default();
        trace!(graph_id = ?graph_id, count = heads.len(), "Retrieved heads");
        Ok(heads)
    }

    async fn put_lockbox_bytes(&self, lakshana: Lakshana, data: &[u8]) -> Result<(), AksharaError> {
        let mut lockboxes = self
            .lockboxes
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = lockboxes.entry(lakshana).or_default();
        entries.push(data.to_vec());
        counter!("akshara.store.put", "type" => "lockbox").increment(1);
        Ok(())
    }

    async fn get_lockboxes_bytes(&self, lakshana: &Lakshana) -> Result<Vec<Vec<u8>>, AksharaError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = lockboxes.get(lakshana).cloned().unwrap_or_default();
        counter!("akshara.store.get", "type" => "lockbox").increment(1);
        Ok(entries)
    }

    async fn put_prekey_bundle_bytes(&self, device_key: &SigningPublicKey, data: &[u8]) -> Result<(), AksharaError> {
        let mut prekeys = self
            .prekeys
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        debug!(device = ?device_key, "Storing pre-key bundle bytes");
        prekeys.insert(device_key.clone(), data.to_vec());
        counter!("akshara.store.put", "type" => "prekey_bundle").increment(1);
        Ok(())
    }

    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &SigningPublicKey,
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        let prekeys = self
            .prekeys
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let result = prekeys.get(device_key).cloned();
        counter!("akshara.store.get", "type" => "prekey_bundle").increment(1);
        Ok(result)
    }

    async fn consume_prekey(
        &self,
        device_key: &SigningPublicKey,
        prekey_index: u32,
    ) -> Result<Option<EncryptionPublicKey>, AksharaError> {
        let mut prekeys = self
            .prekeys
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;

        if let Some(bytes) = prekeys.get_mut(device_key) {
            // THE ATOMIC CONSUMPTION:
            // 1. Deserialize the prekey bundle from bytes.
            let mut bundle: PreKeyBundle = serde_ipld_dagcbor::from_slice(bytes)
                .map_err(|e| AksharaError::InternalError(format!("CBOR deserialization error: {}", e)))?;
            
            // 2. Remove the key.
            let key = bundle.pre_keys.remove(&prekey_index);

            if key.is_some() {
                debug!(device = ?device_key, index = prekey_index, "Consumed one-time pre-key");
                counter!("akshara.store.consume", "type" => "prekey").increment(1);

                // 3. Serialize back and update store.
                let updated_bytes = serde_ipld_dagcbor::to_vec(&bundle)
                    .map_err(|e| AksharaError::InternalError(format!("CBOR serialization error: {}", e)))?;
                *bytes = updated_bytes;
            }
            Ok(key)
        } else {
            Ok(None)
        }
    }
}
