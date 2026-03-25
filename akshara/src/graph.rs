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
    /// * `vault` - Reference to the vault (holds secret keys securely)
    /// * `store` - Storage backend for blocks and manifests
    /// * `staging` - Staging store for buffering operations
    /// * `tuning` - Performance tuning parameters
    pub fn new(
        graph_id: GraphId,
        graph_key: GraphKey,
        vault: Arc<dyn Vault>,
        store: InMemoryStore,
        staging: Arc<Mutex<Box<dyn StagingStore>>>,
        tuning: TuningConfig,
    ) -> Self {
        Self {
            graph_id,
            graph_key,
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
    pub async fn get(&self, _path: &str) -> Result<Vec<u8>> {
        // TODO: Implement path resolution through Merkle-Index
        Err(Error::PathNotFound("not implemented yet".to_string()))
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
    pub async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        // TODO: Implement
        Ok(Vec::new())
    }

    // ========================================================================
    // Sealing
    // ========================================================================

    /// Seal all staged operations into the Merkle-DAG.
    ///
    /// This is the core operation that:
    /// 1. Fetches pending operations
    /// 2. Coalesces operations by path
    /// 3. Creates blocks for each unique path
    /// 4. Builds a Merkle-Index tree
    /// 5. Creates and signs a manifest
    /// 6. Persists everything to storage
    pub async fn seal(&self) -> Result<SealReport> {
        let staging = self.staging.lock().await;
        let operations = staging.fetch_pending().await?;

        if operations.is_empty() {
            return Err(Error::NothingToSeal);
        }

        // Coalesce operations by path
        let coalesced = crate::staging::coalesce_operations(operations);

        // Get identity from vault
        let identity = self.vault.get_identity().await?;

        // Create blocks for each operation
        let mut index_builder = IndexBuilder::new();
        let mut blocks_created = 0;
        let mut bytes_sealed = 0;

        for op in &coalesced {
            match op {
                StagedOperation::Insert { path, data, .. }
                | StagedOperation::Update { path, data, .. } => {
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

                        index_builder.insert(path, akshara_aadhaara::Address::from(block.id()))?;
                    }
                }
                StagedOperation::Delete { .. } => {
                    // TODO: Handle deletes (tombstones)
                    continue;
                }
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
            ManifestId::null(), // TODO: Get identity anchor
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
