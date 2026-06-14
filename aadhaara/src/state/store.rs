use crate::base::address::{BlockId, GraphId, Lakshana, ManifestId};
use crate::base::crypto::{EncryptionPublicKey, Lockbox, SigningPublicKey};
use crate::base::error::AksharaError;
use crate::graph::{Block, Manifest};
use crate::identity::types::PreKeyBundle;
use async_trait::async_trait;

#[async_trait]
pub trait GraphStore: Send + Sync {
    // --- Low-Level Interface (Implementing DB Adapters MUST override these) ---

    /// Writes an immutable block byte blob to the store.
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError>;

    /// Retrieves a block byte blob from the store.
    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError>;

    /// Writes a manifest byte blob, providing explicit indexing parameters.
    async fn put_manifest_bytes(
        &self,
        id: &ManifestId,
        graph_id: &GraphId,
        parents: &[ManifestId],
        data: &[u8],
    ) -> Result<(), AksharaError>;

    /// Retrieves a manifest byte blob from the store.
    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError>;

    /// Retrieves the current heads for a graph.
    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError>;

    /// Appends a lockbox blob associated with a specific blinded address (Lakshana).
    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError>;

    /// Retrieves all lockbox blobs matching a specific Lakshana.
    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError>;

    /// Stores the base prekey bundle for a device.
    async fn put_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
        data: &[u8],
    ) -> Result<(), AksharaError>;

    /// Retrieves the prekey bundle base for a device.
    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Option<Vec<u8>>, AksharaError>;

    /// Writes one-time prekeys for a device.
    async fn put_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
        prekeys: &[(u32, &[u8])],
    ) -> Result<(), AksharaError>;

    /// Retrieves all active one-time prekeys for a device.
    async fn get_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, AksharaError>;

    /// Atomically retrieves and REMOVES a specific pre-key to enforce Forward Secrecy.
    async fn consume_one_time_prekey_bytes(
        &self,
        device_key: &[u8],
        prekey_index: u32,
    ) -> Result<Option<Vec<u8>>, AksharaError>;

    // --- High-Level Interface (Default implementation using low-level methods) ---

    async fn put_block(&self, block: &Block) -> Result<(), AksharaError> {
        let bytes = serde_ipld_dagcbor::to_vec(block)
            .map_err(|e| AksharaError::InternalError(format!("CBOR serialization error: {}", e)))?;
        self.put_block_bytes(&block.id(), &bytes).await
    }

    async fn get_block(&self, id: &BlockId) -> Result<Option<Block>, AksharaError> {
        match self.get_block_bytes(id).await? {
            Some(bytes) => {
                let block: Block = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                    AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
                })?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn put_manifest(&self, manifest: &Manifest) -> Result<(), AksharaError> {
        let bytes = serde_ipld_dagcbor::to_vec(manifest)
            .map_err(|e| AksharaError::InternalError(format!("CBOR serialization error: {}", e)))?;
        self.put_manifest_bytes(
            &manifest.id(),
            &manifest.graph_id(),
            manifest.parents(),
            &bytes,
        )
        .await
    }

    async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>, AksharaError> {
        match self.get_manifest_bytes(id).await? {
            Some(bytes) => {
                let manifest: Manifest = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                    AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
                })?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    async fn put_lockbox(&self, lakshana: Lakshana, lockbox: &Lockbox) -> Result<(), AksharaError> {
        let bytes = serde_ipld_dagcbor::to_vec(lockbox)
            .map_err(|e| AksharaError::InternalError(format!("CBOR serialization error: {}", e)))?;
        self.put_lockbox_bytes(lakshana.as_bytes().as_ref(), &bytes)
            .await
    }

    async fn get_lockboxes(&self, lakshana: &Lakshana) -> Result<Vec<Lockbox>, AksharaError> {
        let lockboxes_bytes = self
            .get_lockboxes_bytes(lakshana.as_bytes().as_ref())
            .await?;
        let mut lockboxes = Vec::with_capacity(lockboxes_bytes.len());
        for bytes in lockboxes_bytes {
            let lockbox: Lockbox = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
            })?;
            lockboxes.push(lockbox);
        }
        Ok(lockboxes)
    }

    async fn put_prekey_bundle(&self, bundle: &PreKeyBundle) -> Result<(), AksharaError> {
        // 1. Write the prekey bundle base
        let bytes = serde_ipld_dagcbor::to_vec(bundle)
            .map_err(|e| AksharaError::InternalError(format!("CBOR serialization error: {}", e)))?;
        let device_key = bundle.device_identity.signing_key();
        self.put_prekey_bundle_bytes(device_key.as_bytes().as_ref(), &bytes)
            .await?;

        // 2. Write one-time prekeys individually
        let mut prekeys_to_store = Vec::with_capacity(bundle.pre_keys.len());
        for (index, key) in &bundle.pre_keys {
            let key_bytes = serde_ipld_dagcbor::to_vec(key).map_err(|e| {
                AksharaError::InternalError(format!("CBOR serialization error: {}", e))
            })?;
            prekeys_to_store.push((*index, key_bytes));
        }

        let prekeys_ref: Vec<(u32, &[u8])> = prekeys_to_store
            .iter()
            .map(|(idx, bytes)| (*idx, bytes.as_slice()))
            .collect();
        self.put_one_time_prekeys_bytes(device_key.as_bytes().as_ref(), &prekeys_ref)
            .await?;

        Ok(())
    }

    async fn get_prekey_bundle(
        &self,
        device_key: &SigningPublicKey,
    ) -> Result<Option<PreKeyBundle>, AksharaError> {
        match self
            .get_prekey_bundle_bytes(device_key.as_bytes().as_ref())
            .await?
        {
            Some(bytes) => {
                let mut bundle: PreKeyBundle =
                    serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                        AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
                    })?;

                // Retrieve active one-time prekeys and populate the bundle
                let prekeys_bytes = self
                    .get_one_time_prekeys_bytes(device_key.as_bytes().as_ref())
                    .await?;
                bundle.pre_keys.clear();
                for (index, key_bytes) in prekeys_bytes {
                    let pub_key: EncryptionPublicKey = serde_ipld_dagcbor::from_slice(&key_bytes)
                        .map_err(|e| {
                        AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
                    })?;
                    bundle.pre_keys.insert(index, pub_key);
                }

                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    async fn consume_prekey(
        &self,
        device_key: &SigningPublicKey,
        prekey_index: u32,
    ) -> Result<Option<EncryptionPublicKey>, AksharaError> {
        match self
            .consume_one_time_prekey_bytes(device_key.as_bytes().as_ref(), prekey_index)
            .await?
        {
            Some(bytes) => {
                let pub_key: EncryptionPublicKey =
                    serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                        AksharaError::InternalError(format!("CBOR deserialization error: {}", e))
                    })?;
                Ok(Some(pub_key))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl<S: GraphStore + ?Sized> GraphStore for std::sync::Arc<S> {
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError> {
        self.as_ref().put_block_bytes(id, data).await
    }

    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError> {
        self.as_ref().get_block_bytes(id).await
    }

    async fn put_manifest_bytes(
        &self,
        id: &ManifestId,
        graph_id: &GraphId,
        parents: &[ManifestId],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        self.as_ref()
            .put_manifest_bytes(id, graph_id, parents, data)
            .await
    }

    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError> {
        self.as_ref().get_manifest_bytes(id).await
    }

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError> {
        self.as_ref().get_heads(graph_id).await
    }

    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError> {
        self.as_ref().put_lockbox_bytes(lakshana, data).await
    }

    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError> {
        self.as_ref().get_lockboxes_bytes(lakshana).await
    }

    async fn put_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        self.as_ref()
            .put_prekey_bundle_bytes(device_key, data)
            .await
    }

    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        self.as_ref().get_prekey_bundle_bytes(device_key).await
    }

    async fn put_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
        prekeys: &[(u32, &[u8])],
    ) -> Result<(), AksharaError> {
        self.as_ref()
            .put_one_time_prekeys_bytes(device_key, prekeys)
            .await
    }

    async fn get_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, AksharaError> {
        self.as_ref().get_one_time_prekeys_bytes(device_key).await
    }

    async fn consume_one_time_prekey_bytes(
        &self,
        device_key: &[u8],
        prekey_index: u32,
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        self.as_ref()
            .consume_one_time_prekey_bytes(device_key, prekey_index)
            .await
    }
}

#[async_trait]
impl<S: GraphStore + ?Sized> GraphStore for &S {
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError> {
        (*self).put_block_bytes(id, data).await
    }

    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError> {
        (*self).get_block_bytes(id).await
    }

    async fn put_manifest_bytes(
        &self,
        id: &ManifestId,
        graph_id: &GraphId,
        parents: &[ManifestId],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        (*self)
            .put_manifest_bytes(id, graph_id, parents, data)
            .await
    }

    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError> {
        (*self).get_manifest_bytes(id).await
    }

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError> {
        (*self).get_heads(graph_id).await
    }

    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError> {
        (*self).put_lockbox_bytes(lakshana, data).await
    }

    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError> {
        (*self).get_lockboxes_bytes(lakshana).await
    }

    async fn put_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        (*self).put_prekey_bundle_bytes(device_key, data).await
    }

    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        (*self).get_prekey_bundle_bytes(device_key).await
    }

    async fn put_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
        prekeys: &[(u32, &[u8])],
    ) -> Result<(), AksharaError> {
        (*self)
            .put_one_time_prekeys_bytes(device_key, prekeys)
            .await
    }

    async fn get_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, AksharaError> {
        (*self).get_one_time_prekeys_bytes(device_key).await
    }

    async fn consume_one_time_prekey_bytes(
        &self,
        device_key: &[u8],
        prekey_index: u32,
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        (*self)
            .consume_one_time_prekey_bytes(device_key, prekey_index)
            .await
    }
}
