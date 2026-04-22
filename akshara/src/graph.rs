//! Graph handle for working with individual graphs.

use std::sync::Arc;
use zeroize::Zeroizing;

use akshara_aadhaara::{
    Block, BlockType, GraphId, GraphKey, GraphStore, InMemoryStore, IndexBuilder, Manifest,
    ManifestId,
};

use crate::config::TuningConfig;
use crate::error::{Error, Result};
use crate::staging::{InMemoryStagingStore, StagedOperation, StagingStore};
use crate::vault::Vault;

/// Handle to a single graph for read/write operations.
///
/// The graph key is held in a `Zeroizing` wrapper and is zeroized on drop.
/// The vault is only accessed during cryptographic operations to minimize
/// secret key lifetime in memory.
pub struct Graph {
    graph_id: GraphId,
    graph_key: Zeroizing<GraphKey>,
    vault: Arc<dyn Vault>,
    store: InMemoryStore,
    staging: Arc<InMemoryStagingStore>,
    tuning: TuningConfig,
    flush_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Graph {
    /// Create a new graph handle.
    pub fn new(
        graph_id: GraphId,
        graph_key: GraphKey,
        vault: Arc<dyn Vault>,
        store: InMemoryStore,
        staging: Arc<InMemoryStagingStore>,
        tuning: TuningConfig,
    ) -> Self {
        Self {
            graph_id,
            graph_key: Zeroizing::new(graph_key),
            vault,
            store,
            staging,
            tuning,
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Get the graph ID.
    pub fn id(&self) -> GraphId {
        self.graph_id
    }

    /// Get the graph key.
    pub fn key(&self) -> &GraphKey {
        &self.graph_key
    }

    /// Get the storage backend.
    pub fn store(&self) -> &InMemoryStore {
        &self.store
    }

    /// Insert new content at the specified path.
    ///
    /// The operation is staged and will be committed when `flush()` is called.
    pub async fn insert(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<()> {
        validate_path(path)?;
        let op = StagedOperation::Insert {
            path: path.to_string(),
            data: data.into(),
            timestamp: current_timestamp(),
        };

        self.staging.stage_operation(op).await?;
        Ok(())
    }

    /// Update existing content at the specified path.
    pub async fn update(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<()> {
        validate_path(path)?;
        let op = StagedOperation::Update {
            path: path.to_string(),
            data: data.into(),
            timestamp: current_timestamp(),
        };

        self.staging.stage_operation(op).await?;
        Ok(())
    }

    /// Delete content at the specified path.
    pub async fn delete(&self, path: &str) -> Result<()> {
        validate_path(path)?;
        let op = StagedOperation::Delete {
            path: path.to_string(),
            timestamp: current_timestamp(),
        };

        self.staging.stage_operation(op).await?;
        Ok(())
    }

    /// Get content at the specified path.
    pub async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Err(Error::PathNotFound(format!(
                "No data sealed yet for path: {}",
                path
            )));
        }

        let manifest_id = heads[0];

        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Manifest not found".to_string()))?;

        let walker = akshara_aadhaara::GraphWalker::new(&self.store);

        let address = walker
            .resolve_path(
                &self.graph_id,
                manifest.content_root(),
                path,
                &self.graph_key,
            )
            .await
            .map_err(|e| {
                Error::PathNotFound(format!("Path resolution failed for '{}': {}", path, e))
            })?;

        let block_id: akshara_aadhaara::BlockId = address
            .try_into()
            .map_err(|e| Error::Internal(format!("Address to BlockId conversion failed: {}", e)))?;

        let block = self
            .store
            .get_block(&block_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| Error::PathNotFound(format!("Block not found for path: {}", path)))?;

        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        Ok(content)
    }

    /// Fetch raw bytes at a path without deserializing into a typed document.
    ///
    /// Used for large binary data (files, images, PDFs) that the developer
    /// wants to handle directly. For `#[chunked]` fields, this reassembles
    /// all chunks transparently.
    pub async fn fetch_blob(&self, path: &str) -> Result<Vec<u8>> {
        // Reuses the same path resolution as get()
        self.get(path).await
    }

    /// Returns the BlockId (CID) for the specified path.
    pub async fn get_id(&self, path: &str) -> Result<akshara_aadhaara::BlockId> {
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Err(Error::PathNotFound(format!(
                "No data sealed yet for path: {}",
                path
            )));
        }

        let manifest_id = heads[0];
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Manifest not found".to_string()))?;

        let walker = akshara_aadhaara::GraphWalker::new(&self.store);

        let address = walker
            .resolve_path(
                &self.graph_id,
                manifest.content_root(),
                path,
                &self.graph_key,
            )
            .await
            .map_err(|e| {
                Error::PathNotFound(format!("Path resolution failed for '{}': {}", path, e))
            })?;

        akshara_aadhaara::BlockId::try_from(address)
            .map_err(|e| Error::Internal(format!("Address conversion failed: {}", e)))
    }

    /// Check if content exists at the specified path.
    pub async fn exists(&self, path: &str) -> Result<bool> {
        match self.get(path).await {
            Ok(_) => Ok(true),
            Err(Error::PathNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// List all paths with the given prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Ok(Vec::new());
        }

        let manifest_id = heads[0];
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Manifest not found".to_string()))?;

        if prefix.is_empty() || prefix == "/" {
            let mut paths = Vec::new();
            self.collect_paths(manifest.content_root(), "", &mut paths)
                .await?;
            return Ok(paths);
        }

        let walker = akshara_aadhaara::GraphWalker::new(&self.store);

        match walker
            .resolve_path(
                &self.graph_id,
                manifest.content_root(),
                prefix,
                &self.graph_key,
            )
            .await
        {
            Ok(address) => {
                if let Ok(index_id) = akshara_aadhaara::BlockId::try_from(address) {
                    let mut paths = Vec::new();
                    self.collect_paths(index_id, prefix, &mut paths).await?;
                    return Ok(paths);
                }
            }
            Err(_) => return Ok(Vec::new()),
        }

        Ok(Vec::new())
    }

    /// Recursively collect paths from the index tree.
    async fn collect_paths(
        &self,
        index_id: akshara_aadhaara::BlockId,
        prefix: &str,
        paths: &mut Vec<String>,
    ) -> Result<()> {
        let block = self
            .store
            .get_block(&index_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get index block: {}", e)))?
            .ok_or_else(|| Error::Internal("Index block not found".to_string()))?;

        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        let index_map: std::collections::BTreeMap<String, akshara_aadhaara::Address> =
            akshara_aadhaara::from_canonical_bytes(&content)
                .map_err(|e| Error::Internal(format!("Failed to parse index: {}", e)))?;

        for (key, address) in index_map {
            let full_path = if prefix.is_empty() {
                format!("/{}", key)
            } else {
                format!("{}/{}", prefix, key)
            };

            if let Ok(block_id) = akshara_aadhaara::BlockId::try_from(address)
                && let Ok(Some(child_block)) = self.store.get_block(&block_id).await
            {
                match child_block.block_type() {
                    akshara_aadhaara::BlockType::AksharaIndexV1 => {
                        Box::pin(self.collect_paths(block_id, &full_path, paths)).await?;
                    }
                    _ => {
                        paths.push(full_path);
                    }
                }
            }
        }

        Ok(())
    }

    /// Flush all staged operations into the Merkle-DAG.
    ///
    /// This is the core operation that coalesces pending writes by path,
    /// creates blocks with proper lineage, builds the Merkle index, and
    /// signs a manifest checkpoint.
    pub async fn flush(&self) -> Result<FlushReport> {
        let _lock = self.flush_lock.lock().await;

        let operations = self.staging.fetch_pending().await?;
        if operations.is_empty() {
            return Err(Error::NothingToFlush);
        }

        let coalesced = crate::staging::coalesce_operations(operations);
        let mut current_state = self.load_current_state().await?;

        for op in &coalesced {
            match op {
                StagedOperation::Insert { path, data, .. }
                | StagedOperation::Update { path, data, .. } => {
                    let prev_id_opt = current_state.get(path).map(|(_, id)| *id);
                    current_state.insert(
                        path.clone(),
                        (
                            data.clone(),
                            prev_id_opt.unwrap_or(akshara_aadhaara::BlockId::null()),
                        ),
                    );
                }
                StagedOperation::Delete { path, .. } => {
                    current_state.remove(path);
                }
            }
        }

        let master_identity = self.vault.get_identity(None).await?;

        // AKSHARA RITUAL (Privacy Preservation):
        // We use a Graph-Isolated Shadow Identity to sign all manifests.
        // This prevents the Relay from linking different graphs to the same user.
        let identity = self.vault.get_identity(Some(&self.graph_id)).await?;

        let mut index_builder = IndexBuilder::new();
        let mut blocks_created = 0;
        let mut bytes_flushed = 0;

        for (path, (data, prev_id)) in current_state {
            if data.len() > self.tuning.max_block_size {
                return Err(Error::BlockSizeExceeded {
                    path: path.clone(),
                    size: data.len(),
                    max: self.tuning.max_block_size,
                });
            }

            // If this is an update, chain the new block to the previous one.
            let parents = if prev_id != akshara_aadhaara::BlockId::null() {
                vec![prev_id]
            } else {
                vec![]
            };

            let block = Block::new(
                self.graph_id,
                data.clone(),
                BlockType::AksharaDataV1,
                parents,
                &self.graph_key,
                &identity,
            )?;

            self.store.put_block(&block).await?;
            blocks_created += 1;
            bytes_flushed += data.len();

            index_builder.insert(&path, akshara_aadhaara::Address::from(block.id()))?;
        }

        let root_index_id = index_builder
            .build(self.graph_id, &self.store, &identity, &self.graph_key)
            .await?;

        let parents = self
            .store
            .get_heads(&self.graph_id)
            .await
            .unwrap_or_default();

        let identity_anchor = self.vault.latest_identity_anchor();

        // AKSHARA RITUAL: Generate a Shadow Certificate so the Auditor can verify
        // this shadow identity using the GraphKey.
        let mut rng = rand::rngs::OsRng;
        let authority_proof = master_identity
            .create_shadow_certificate(
                identity.public().signing_key(),
                &self.graph_id,
                &self.graph_key,
                &mut rng,
            )
            .ok();

        let manifest = Manifest::new(
            self.graph_id,
            root_index_id,
            parents,
            identity_anchor,
            &identity,
            authority_proof,
        );

        self.store.put_manifest(&manifest).await?;

        let max_timestamp = coalesced.iter().map(|op| op.timestamp()).max().unwrap_or(0);
        self.staging.clear_committed(max_timestamp).await?;

        Ok(FlushReport {
            manifest_id: manifest.id(),
            blocks_created,
            bytes_flushed: bytes_flushed as u64,
            operations_coalesced: coalesced.len(),
        })
    }

    /// Load current state from the latest manifest (CRDT-style reconstruction).
    ///
    /// O(N) in the number of blocks — an LRU cache is planned for v0.2.
    async fn load_current_state(
        &self,
    ) -> Result<std::collections::BTreeMap<String, (Vec<u8>, akshara_aadhaara::BlockId)>> {
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Ok(std::collections::BTreeMap::new());
        }

        let manifest_id = heads[0];
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Latest manifest not found".to_string()))?;

        let mut state = std::collections::BTreeMap::new();
        self.load_state_from_index(manifest.content_root(), "", &mut state)
            .await?;

        Ok(state)
    }

    /// Recursively load state from the Merkle index tree.
    async fn load_state_from_index(
        &self,
        index_id: akshara_aadhaara::BlockId,
        prefix: &str,
        state: &mut std::collections::BTreeMap<String, (Vec<u8>, akshara_aadhaara::BlockId)>,
    ) -> Result<()> {
        let block = self
            .store
            .get_block(&index_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get index block: {}", e)))?
            .ok_or_else(|| Error::Internal("Index block not found".to_string()))?;

        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        let index_map: std::collections::BTreeMap<String, akshara_aadhaara::Address> =
            akshara_aadhaara::from_canonical_bytes(&content)
                .map_err(|e| Error::Internal(format!("Failed to parse index: {}", e)))?;

        for (key, address) in index_map {
            let full_path = if prefix.is_empty() {
                format!("/{}", key)
            } else {
                format!("{}/{}", prefix, key)
            };

            if let Ok(block_id) = akshara_aadhaara::BlockId::try_from(address)
                && let Ok(Some(child_block)) = self.store.get_block(&block_id).await
            {
                match child_block.block_type() {
                    akshara_aadhaara::BlockType::AksharaIndexV1 => {
                        Box::pin(self.load_state_from_index(block_id, &full_path, state)).await?;
                    }
                    _ => {
                        let data = child_block
                            .decrypt(&self.graph_id, &self.graph_key)
                            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;
                        state.insert(full_path, (data, block_id));
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn sync(&self) -> Result<SyncReport> {
        let transport = Arc::new(crate::sync::MockTransport::new());
        let engine = crate::sync::SyncEngine::new(transport, self.vault.clone());
        engine
            .sync_graph(self.graph_id, &self.store, &self.graph_key)
            .await
    }
}

/// Report from a flush operation.
#[derive(Debug, Clone)]
pub struct FlushReport {
    /// The manifest ID that was created
    pub manifest_id: ManifestId,
    /// Number of blocks created
    pub blocks_created: usize,
    /// Total bytes flushed
    pub bytes_flushed: u64,
    /// Number of operations coalesced
    pub operations_coalesced: usize,
}

/// Report from a sync operation.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Number of graphs synchronized
    pub graphs_synced: usize,
    /// Number of manifests received
    pub manifests_received: usize,
    /// Number of blocks received
    pub blocks_received: usize,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Number of conflicts detected
    pub conflicts_detected: usize,
}

/// Validate a path string.
///
/// Paths must start with `/`, contain no null bytes, and not exceed 1024
/// characters. Reserved `.akshara.*` segments are also rejected.
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must start with /".to_string(),
        });
    }
    if path.contains('\0') {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not contain null bytes".to_string(),
        });
    }
    if path.len() > 1024 {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not exceed 1024 characters".to_string(),
        });
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not contain relative path segments (. or ..)".to_string(),
        });
    }
    if path.split('/').any(|seg| seg.starts_with(".akshara.")) {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must not use reserved .akshara.* segments".to_string(),
        });
    }
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;
    use crate::vault::create_vault;
    use akshara_aadhaara::SecretIdentity;

    async fn create_test_graph() -> Graph {
        let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
        let config = ClientConfig::new().with_ephemeral_vault();
        let vault = create_vault(config.vault().clone()).unwrap();
        vault.initialize(Some(mnemonic)).await.unwrap();

        let identity = vault.get_identity(None).await.unwrap();
        let store = InMemoryStore::new();
        let graph_id = GraphId::new();
        let graph_key = identity.derive_graph_key(&graph_id).unwrap();

        Graph::new(
            graph_id,
            graph_key,
            vault,
            store,
            Arc::new(InMemoryStagingStore::new()),
            TuningConfig::default(),
        )
    }

    #[tokio::test]
    async fn test_block_lineage_is_preserved_during_flush() {
        let graph = create_test_graph().await;
        let path = "/test/lineage";

        // 1. Initial write
        graph.insert(path, b"v1").await.unwrap();
        graph.flush().await.unwrap();
        let id1 = graph.get_id(path).await.unwrap();

        // 2. Update the same path
        graph.update(path, b"v2").await.unwrap();
        graph.flush().await.unwrap();
        let id2 = graph.get_id(path).await.unwrap();

        // 3. Verify that the new block points to the old block as its parent
        let block2 = graph
            .store
            .get_block(&id2)
            .await
            .unwrap()
            .expect("Block 2 should exist");

        assert_ne!(id1, id2, "Block IDs must change when content changes");
        assert!(
            block2.parents().contains(&id1),
            "Updated block should list previous version {} as parent. Found: {:?}",
            id1,
            block2.parents()
        );
    }

    #[tokio::test]
    async fn test_multi_generation_lineage() {
        let graph = create_test_graph().await;
        let path = "/test/generations";

        // G1
        graph.insert(path, b"gen1").await.unwrap();
        graph.flush().await.unwrap();
        let id1 = graph.get_id(path).await.unwrap();

        // G2
        graph.update(path, b"gen2").await.unwrap();
        graph.flush().await.unwrap();
        let id2 = graph.get_id(path).await.unwrap();

        // G3
        graph.update(path, b"gen3").await.unwrap();
        graph.flush().await.unwrap();
        let id3 = graph.get_id(path).await.unwrap();

        // Verify G3 points to G2
        let b3 = graph.store.get_block(&id3).await.unwrap().unwrap();
        assert!(b3.parents().contains(&id2));

        // Verify G2 points to G1
        let b2 = graph.store.get_block(&id2).await.unwrap().unwrap();
        assert!(b2.parents().contains(&id1));
    }

    #[tokio::test]
    async fn test_lineage_after_deletion_and_reinsertion() {
        let graph = create_test_graph().await;
        let path = "/test/reset";

        // 1. Insert and Flush
        graph.insert(path, b"first").await.unwrap();
        graph.flush().await.unwrap();
        let id1 = graph.get_id(path).await.unwrap();

        // 2. Delete and Flush
        graph.delete(path).await.unwrap();
        graph.flush().await.unwrap();
        assert!(
            graph.get_id(path).await.is_err(),
            "Path should be gone after delete"
        );

        // 3. Re-insert and Flush
        graph.insert(path, b"second").await.unwrap();
        graph.flush().await.unwrap();
        let id2 = graph.get_id(path).await.unwrap();

        // 4. Verify that re-insertion starts a NEW lineage (no parents)
        let b2 = graph.store.get_block(&id2).await.unwrap().unwrap();
        assert!(
            b2.parents().is_empty(),
            "Re-insertion after deletion should have no parents"
        );
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_coalesced_update_lineage() {
        let graph = create_test_graph().await;
        let path = "/test/coalesce";

        // 1. Initial stable state
        graph.insert(path, b"original").await.unwrap();
        graph.flush().await.unwrap();
        let id_orig = graph.get_id(path).await.unwrap();

        // 2. Stage multiple updates BEFORE flushing
        graph.update(path, b"temp1").await.unwrap();
        graph.update(path, b"temp2").await.unwrap();
        graph.update(path, b"final").await.unwrap();

        // 3. Seal (should coalesce to just "final")
        graph.flush().await.unwrap();
        let id_final = graph.get_id(path).await.unwrap();

        // 4. Verify that "final" points to "original", skipping the temp states
        let b_final = graph.store.get_block(&id_final).await.unwrap().unwrap();
        assert!(b_final.parents().contains(&id_orig));
        assert_eq!(b_final.parents().len(), 1);
    }

    // ========================================================================
    // Purposeful Error-Path Tests
    // ========================================================================

    #[tokio::test]
    async fn flush_on_empty_staging_returns_nothing_to_flush() {
        // If this silently succeeds, the developer wastes CPU building an empty
        // manifest. If it panics, the app crashes. The error must fire.
        let graph = create_test_graph().await;
        let result = graph.flush().await;
        assert!(matches!(result, Err(Error::NothingToFlush)));
    }

    #[tokio::test]
    async fn flush_with_oversized_data_returns_block_size_exceeded() {
        // Guards the BlockSizeExceeded error path. We just fixed the path field
        // to actually carry the path string — without this test, nobody would
        // notice if it regressed to String::new().
        let graph = create_test_graph().await;
        let path = "/test/large-file";
        let oversized = vec![0u8; graph.tuning.max_block_size + 1];

        graph.insert(path, oversized).await.unwrap();
        let result = graph.flush().await;

        match result {
            Err(Error::BlockSizeExceeded { path: p, size, max }) => {
                assert_eq!(p, path);
                assert!(size > max);
            }
            other => panic!("Expected BlockSizeExceeded, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fetch_blob_returns_raw_bytes() {
        let graph = create_test_graph().await;
        let path = "/blob/data";
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        graph.insert(path, data.clone()).await.unwrap();
        graph.flush().await.unwrap();

        let blob = graph.fetch_blob(path).await.unwrap();
        assert_eq!(blob, data);
    }

    #[tokio::test]
    async fn fetch_blob_on_missing_path_returns_not_found() {
        let graph = create_test_graph().await;
        graph.insert("/doc", b"hello").await.unwrap();
        graph.flush().await.unwrap();

        let result = graph.fetch_blob("/missing/path").await;
        assert!(matches!(result, Err(Error::PathNotFound(_))));
    }

    #[tokio::test]
    async fn insert_rejects_invalid_paths() {
        // If invalid paths silently succeed, they create broken index entries
        // that are impossible to resolve later.
        let graph = create_test_graph().await;

        // Missing leading slash
        let result = graph.insert("no-slash", b"data").await;
        assert!(
            matches!(result, Err(Error::InvalidPath { .. })),
            "Expected InvalidPath for missing leading slash"
        );

        // Empty path
        let result = graph.insert("", b"data").await;
        assert!(
            matches!(result, Err(Error::InvalidPath { .. })),
            "Expected InvalidPath for empty path"
        );

        // Null byte
        let result = graph.insert("/test/null\0byte", b"data").await;
        assert!(
            matches!(result, Err(Error::InvalidPath { .. })),
            "Expected InvalidPath for null byte"
        );
    }
}
