use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::error::{AksharaError, StoreError};

use crate::state::store::GraphStore;
use async_trait::async_trait;
use metrics::counter;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

type LockboxMap = HashMap<Vec<u8>, Vec<Vec<u8>>>;
type PreKeyMap = HashMap<Vec<u8>, Vec<u8>>;
type OneTimePreKeyMap = HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>;

#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    pub(crate) blocks: Arc<RwLock<HashMap<BlockId, Vec<u8>>>>,
    pub(crate) manifests: Arc<RwLock<HashMap<ManifestId, Vec<u8>>>>,
    pub(crate) heads: Arc<RwLock<HashMap<GraphId, Vec<ManifestId>>>>,
    pub(crate) lockboxes: Arc<RwLock<LockboxMap>>,
    pub(crate) prekeys: Arc<RwLock<PreKeyMap>>,
    pub(crate) one_time_prekeys: Arc<RwLock<OneTimePreKeyMap>>,
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
        blocks.insert(*id, data.to_vec());
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
            manifests.insert(*id, data.to_vec());
        }

        // 2. Update Heads
        let mut heads_map = self
            .heads
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let graph_heads = heads_map.entry(*graph_id).or_default();

        // If this manifest replaces parents, remove those parents from heads
        for parent in parents {
            graph_heads.retain(|h| h != parent);
        }

        // Add this manifest as a new head
        if !graph_heads.contains(id) {
            graph_heads.push(*id);
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

    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError> {
        let mut lockboxes = self
            .lockboxes
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = lockboxes.entry(lakshana.to_vec()).or_default();
        entries.push(data.to_vec());
        counter!("akshara.store.put", "type" => "lockbox").increment(1);
        Ok(())
    }

    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError> {
        let lockboxes = self
            .lockboxes
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = lockboxes.get(lakshana).cloned().unwrap_or_default();
        counter!("akshara.store.get", "type" => "lockbox").increment(1);
        Ok(entries)
    }

    async fn put_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        let mut prekeys = self
            .prekeys
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        debug!("Storing pre-key bundle bytes");
        prekeys.insert(device_key.to_vec(), data.to_vec());
        counter!("akshara.store.put", "type" => "prekey_bundle").increment(1);
        Ok(())
    }

    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        let prekeys = self
            .prekeys
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let result = prekeys.get(device_key).cloned();
        counter!("akshara.store.get", "type" => "prekey_bundle").increment(1);
        Ok(result)
    }

    async fn put_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
        prekeys: &[(u32, &[u8])],
    ) -> Result<(), AksharaError> {
        let mut one_time_prekeys = self
            .one_time_prekeys
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = one_time_prekeys.entry(device_key.to_vec()).or_default();
        for (index, key_bytes) in prekeys {
            entries.insert(*index, key_bytes.to_vec());
        }
        Ok(())
    }

    async fn get_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, AksharaError> {
        let one_time_prekeys = self
            .one_time_prekeys
            .read()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let entries = one_time_prekeys
            .get(device_key)
            .cloned()
            .unwrap_or_default();
        let result = entries.into_iter().collect();
        Ok(result)
    }

    async fn consume_one_time_prekey_bytes(
        &self,
        device_key: &[u8],
        prekey_index: u32,
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        let mut one_time_prekeys = self
            .one_time_prekeys
            .write()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        if let Some(entries) = one_time_prekeys.get_mut(device_key) {
            let key = entries.remove(&prekey_index);
            if key.is_some() {
                debug!(index = prekey_index, "Consumed one-time pre-key");
                counter!("akshara.store.consume", "type" => "prekey").increment(1);
            }
            Ok(key)
        } else {
            Ok(None)
        }
    }
}
