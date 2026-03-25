//! Graph handle for working with individual graphs.

use std::sync::Arc;
use tokio::sync::Mutex;

use akshara_aadhaara::{
    Block, BlockType, GraphId, GraphKey, GraphStore, InMemoryStore, IndexBuilder, Manifest,
    ManifestId,
};

use crate::config::TuningConfig;
use crate::error::{Error, Result};
use crate::staging::{StagedOperation, StagingStore};
use crate::vault::Vault;

/// Handle to a single graph for read/write operations.
///
/// # Security Design
///
/// This struct does NOT hold secret keys. Instead, it holds a reference to the
/// vault, which is locked only when cryptographic operations are needed.
/// This ensures secret keys have minimal lifetime in memory.
pub struct Graph {
    graph_id: GraphId,
    graph_key: GraphKey,
    identity_anchor: ManifestId,
    vault: Arc<dyn Vault>,
    store: InMemoryStore,
    staging: Arc<Mutex<Box<dyn StagingStore>>>,
    tuning: TuningConfig,
}

impl Graph {
    /// Create a new graph handle.
    ///
    /// # Arguments
    ///
    /// * `graph_id` - The graph identifier
    /// * `graph_key` - The symmetric encryption key for this graph
    /// * `identity_anchor` - The latest known identity state CID
    /// * `vault` - Reference to the vault (holds secret keys securely)
    /// * `store` - Storage backend for blocks and manifests
    /// * `staging` - Staging store for buffering operations
    /// * `tuning` - Performance tuning parameters
    pub fn new(
        graph_id: GraphId,
        graph_key: GraphKey,
        identity_anchor: ManifestId,
        vault: Arc<dyn Vault>,
        store: InMemoryStore,
        staging: Arc<Mutex<Box<dyn StagingStore>>>,
        tuning: TuningConfig,
    ) -> Self {
        Self {
            graph_id,
            graph_key,
            identity_anchor,
            vault,
            store,
            staging,
            tuning,
        }
    }

    /// Get the graph ID.
    pub fn id(&self) -> GraphId {
        self.graph_id
    }

    // ========================================================================
    // Staged Writes
    // ========================================================================

    /// Insert new content at the specified path.
    ///
    /// The operation is staged and will be committed when `seal()` is called.
    pub async fn insert(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<()> {
        let op = StagedOperation::Insert {
            path: path.to_string(),
            data: data.into(),
            timestamp: current_timestamp(),
        };

        let staging = self.staging.lock().await;
        staging.stage_operation(op).await?;
        Ok(())
    }

    /// Update existing content at the specified path.
    pub async fn update(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<()> {
        let op = StagedOperation::Update {
            path: path.to_string(),
            data: data.into(),
            timestamp: current_timestamp(),
        };

        let staging = self.staging.lock().await;
        staging.stage_operation(op).await?;
        Ok(())
    }

    /// Delete content at the specified path.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let op = StagedOperation::Delete {
            path: path.to_string(),
            timestamp: current_timestamp(),
        };

        let staging = self.staging.lock().await;
        staging.stage_operation(op).await?;
        Ok(())
    }

    // ========================================================================
    // Reads
    // ========================================================================

    /// Get content at the specified path.
    pub async fn get(&self, path: &str) -> Result<Vec<u8>> {
        // Get current heads from store
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

        // Use the first head (for now, single-head assumption)
        let manifest_id = heads[0];

        // Get the manifest
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Manifest not found".to_string()))?;

        // Get identity from vault for path resolution
        let identity = self.vault.get_identity().await?;

        // Use GraphWalker to resolve the path
        let walker = akshara_aadhaara::GraphWalker::new(
            &self.store,
            identity.public().signing_key().clone(),
        );

        // Resolve path to get the block address
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

        // Convert Address to BlockId
        let block_id: akshara_aadhaara::BlockId = address
            .try_into()
            .map_err(|e| Error::Internal(format!("Address to BlockId conversion failed: {}", e)))?;

        // Get the block
        let block = self
            .store
            .get_block(&block_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| Error::PathNotFound(format!("Block not found for path: {}", path)))?;

        // Decrypt and return content
        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        Ok(content)
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
        // Get current heads from store
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Ok(Vec::new());
        }

        // Use the first head
        let manifest_id = heads[0];

        // Get the manifest
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Manifest not found".to_string()))?;

        // If prefix is empty, collect from root
        if prefix.is_empty() || prefix == "/" {
            let mut paths = Vec::new();
            self.collect_paths(manifest.content_root(), "", &mut paths)
                .await?;
            return Ok(paths);
        }

        // Otherwise, navigate to the prefix path first
        let identity = self.vault.get_identity().await?;
        let walker = akshara_aadhaara::GraphWalker::new(
            &self.store,
            identity.public().signing_key().clone(),
        );

        // Try to resolve the prefix path
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
                // Convert to BlockId and collect paths from there
                if let Ok(index_id) = akshara_aadhaara::BlockId::try_from(address) {
                    let mut paths = Vec::new();
                    self.collect_paths(index_id, prefix, &mut paths).await?;
                    return Ok(paths);
                }
            }
            Err(_) => {
                // Prefix path doesn't exist - return empty
                return Ok(Vec::new());
            }
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
        // Get the index block
        let block = self
            .store
            .get_block(&index_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get index block: {}", e)))?
            .ok_or_else(|| Error::Internal("Index block not found".to_string()))?;

        // Decrypt the index content
        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        // Parse as BTreeMap<String, Address>
        let index_map: std::collections::BTreeMap<String, akshara_aadhaara::Address> =
            akshara_aadhaara::from_canonical_bytes(&content)
                .map_err(|e| Error::Internal(format!("Failed to parse index: {}", e)))?;

        for (key, address) in index_map {
            let full_path = if prefix.is_empty() {
                format!("/{}", key)
            } else {
                format!("{}/{}", prefix, key)
            };

            // Check if this is a data block or another index by trying to convert to BlockId
            // and checking the block type
            if let Ok(block_id) = akshara_aadhaara::BlockId::try_from(address) {
                // Get the block to check its type
                if let Ok(Some(child_block)) = self.store.get_block(&block_id).await {
                    match child_block.block_type() {
                        akshara_aadhaara::BlockType::AksharaIndexV1 => {
                            // Index block - recurse with Box::pin to avoid infinite size
                            Box::pin(self.collect_paths(block_id, &full_path, paths)).await?;
                        }
                        _ => {
                            // Data block - add to paths
                            paths.push(full_path);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // Sealing
    // ========================================================================

    /// Seal all staged operations into the Merkle-DAG.
    ///
    /// This is the core operation that:
    /// 1. Fetches pending operations
    /// 2. Coalesces operations by path
    /// 3. Loads current state from latest manifest (CRDT-style merge)
    /// 4. Applies staged operations to current state
    /// 5. Creates blocks for each unique path
    /// 6. Builds a Merkle-Index tree
    /// 7. Creates and signs a manifest
    /// 8. Persists everything to storage
    pub async fn seal(&self) -> Result<SealReport> {
        let staging = self.staging.lock().await;
        let operations = staging.fetch_pending().await?;

        if operations.is_empty() {
            return Err(Error::NothingToSeal);
        }

        // Coalesce operations by path
        let coalesced = crate::staging::coalesce_operations(operations);

        // CRDT-style: Load current state from latest manifest
        let mut current_state = self.load_current_state().await?;

        // Apply staged operations to current state (CRDT merge)
        for op in &coalesced {
            match op {
                StagedOperation::Insert { path, data, .. }
                | StagedOperation::Update { path, data, .. } => {
                    current_state.insert(path.clone(), data.clone());
                }
                StagedOperation::Delete { path, .. } => {
                    current_state.remove(path);
                }
            }
        }

        // Get identity from vault
        let master_identity = self.vault.get_identity().await?;

        // SHADOW IDENTITY RITUAL: Derive a graph-isolated identity for signing
        let identity = master_identity.derive_shadow_identity(&self.graph_id)?;

        // Create blocks for each path in merged state
        let mut index_builder = IndexBuilder::new();
        let mut blocks_created = 0;
        let mut bytes_sealed = 0;

        for (path, data) in current_state {
            // Check if we need to chunk
            if data.len() > self.tuning.max_block_size {
                // Chunk large payload - TODO: implement
                return Err(Error::ChunkingFailed("not implemented yet".to_string()));
            } else {
                // Single block
                let block = Block::new(
                    self.graph_id,
                    data.clone(),
                    BlockType::AksharaDataV1,
                    vec![],
                    &self.graph_key,
                    &identity,
                )?;

                self.store.put_block(&block).await?;
                blocks_created += 1;
                bytes_sealed += data.len();

                index_builder.insert(&path, akshara_aadhaara::Address::from(block.id()))?;
            }
        }

        // Build the Merkle-Index tree
        let root_index_id = index_builder
            .build(self.graph_id, &self.store, &identity, &self.graph_key)
            .await?;

        // Get current heads for parents
        let parents = self
            .store
            .get_heads(&self.graph_id)
            .await
            .unwrap_or_default();

        // Create manifest
        let manifest = Manifest::new(
            self.graph_id,
            root_index_id,
            parents,
            self.identity_anchor,
            &identity,
        );

        self.store.put_manifest(&manifest).await?;

        // Clear staged operations
        let max_timestamp = coalesced.iter().map(|op| op.timestamp()).max().unwrap_or(0);
        staging.clear_committed(max_timestamp).await?;

        drop(staging);

        Ok(SealReport {
            manifest_id: manifest.id(),
            blocks_created,
            bytes_sealed: bytes_sealed as u64,
            operations_coalesced: coalesced.len(),
        })
    }

    /// Load current state from the latest manifest.
    ///
    /// This implements the CRDT-style state reconstruction by reading
    /// the current index and loading all data blocks.
    async fn load_current_state(&self) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        // Get current heads
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            // No previous state - start fresh
            return Ok(std::collections::BTreeMap::new());
        }

        // Use the first head (latest manifest)
        let manifest_id = heads[0];
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Latest manifest not found".to_string()))?;

        // Load all paths from the index
        let mut state = std::collections::BTreeMap::new();
        self.load_state_from_index(manifest.content_root(), &mut state)
            .await?;

        Ok(state)
    }

    /// Recursively load state from index tree.
    async fn load_state_from_index(
        &self,
        index_id: akshara_aadhaara::BlockId,
        state: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        // Get the index block
        let block = self
            .store
            .get_block(&index_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get index block: {}", e)))?
            .ok_or_else(|| Error::Internal("Index block not found".to_string()))?;

        // Decrypt the index content
        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        // Parse as BTreeMap<String, Address>
        let index_map: std::collections::BTreeMap<String, akshara_aadhaara::Address> =
            akshara_aadhaara::from_canonical_bytes(&content)
                .map_err(|e| Error::Internal(format!("Failed to parse index: {}", e)))?;

        for (key, address) in index_map {
            let full_path = format!("/{}", key);

            // Try to convert to BlockId and load the block
            if let Ok(block_id) = akshara_aadhaara::BlockId::try_from(address)
                && let Ok(Some(child_block)) = self.store.get_block(&block_id).await
            {
                match child_block.block_type() {
                    akshara_aadhaara::BlockType::AksharaIndexV1 => {
                        // Index block - recurse with Box::pin to avoid infinite size
                        Box::pin(self.load_state_from_index(block_id, state)).await?;
                    }
                    _ => {
                        // Data block - decrypt and add to state
                        let data = child_block
                            .decrypt(&self.graph_id, &self.graph_key)
                            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;
                        state.insert(full_path, data);
                    }
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // Sync
    // ========================================================================

    /// Synchronize this graph with the relay.
    pub async fn sync(&self) -> Result<SyncReport> {
        // TODO: Implement sync
        Ok(SyncReport {
            graphs_synced: 1,
            manifests_received: 0,
            blocks_received: 0,
            bytes_transferred: 0,
            conflicts_detected: 0,
        })
    }
}

/// Report from a seal operation.
#[derive(Debug, Clone)]
pub struct SealReport {
    /// The manifest ID that was created
    pub manifest_id: ManifestId,
    /// Number of blocks created
    pub blocks_created: usize,
    /// Total bytes sealed
    pub bytes_sealed: u64,
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

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
