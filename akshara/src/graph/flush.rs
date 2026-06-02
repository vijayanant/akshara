use std::collections::{BTreeMap, HashSet};

use super::{Graph, core::StateValue};
use crate::error::{Error, Result};
use crate::staging::{StagedOperation, StagingStore};
use akshara_aadhaara::{Block, BlockType, GraphStore, IndexBuilder, Manifest, ManifestId};

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

impl Graph {
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
                            StateValue::Data(data.clone()),
                            prev_id_opt.unwrap_or(akshara_aadhaara::BlockId::null()),
                        ),
                    );
                }
                StagedOperation::Link { path, address, .. } => {
                    let prev_id_opt = current_state.get(path).map(|(_, id)| *id);
                    current_state.insert(
                        path.clone(),
                        (
                            StateValue::Link(*address),
                            prev_id_opt.unwrap_or(akshara_aadhaara::BlockId::null()),
                        ),
                    );
                }
                StagedOperation::Delete { path, .. } => {
                    current_state.remove(path);
                }
            }
        }

        let modified_paths: HashSet<String> =
            coalesced.iter().map(|op| op.path().to_string()).collect();

        // AKSHARA RITUAL (Privacy Preservation):
        // We use a Graph-Isolated Shadow Identity to sign all manifests.
        // This prevents the Relay from linking different graphs to the same user.
        let identity = self.vault.get_identity(Some(&self.graph_id)).await?;

        let mut index_builder = IndexBuilder::new();
        let mut blocks_created = 0;
        let mut bytes_flushed = 0;

        for (path, (val, block_or_prev_id)) in current_state {
            match val {
                StateValue::Data(data) => {
                    if modified_paths.contains(&path) {
                        if data.len() > self.tuning.max_block_size {
                            return Err(Error::BlockSizeExceeded {
                                path: path.clone(),
                                size: data.len(),
                                max: self.tuning.max_block_size,
                            });
                        }

                        // If this is an update, chain the new block to the previous one.
                        let parents = if block_or_prev_id != akshara_aadhaara::BlockId::null() {
                            vec![block_or_prev_id]
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
                    } else {
                        // For unmodified files, simply re-insert the existing block ID
                        index_builder
                            .insert(&path, akshara_aadhaara::Address::from(block_or_prev_id))?;
                    }
                }
                StateValue::Link(address) => {
                    index_builder.insert(&path, address)?;
                }
            }
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

        let master_identity = self.vault.get_executive_identity().await?;
        let mut rng = rand::rngs::OsRng;
        let authority_proof = master_identity
            .create_shadow_certificate(
                identity.public().signing_key(),
                &self.graph_id,
                &self.graph_key,
                &mut rng,
            )
            .map_err(Error::Protocol)?;

        let manifest = Manifest::new(
            self.graph_id,
            root_index_id,
            parents,
            identity_anchor,
            akshara_aadhaara::Address::null(),
            &identity,
            Some(authority_proof),
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
    ) -> Result<BTreeMap<String, (StateValue, akshara_aadhaara::BlockId)>> {
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Ok(BTreeMap::new());
        }

        let manifest_id = heads[0];
        let manifest = self
            .store
            .get_manifest(&manifest_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get manifest: {}", e)))?
            .ok_or_else(|| Error::Internal("Latest manifest not found".to_string()))?;

        let mut state = BTreeMap::new();
        self.load_state_from_index(manifest.content_root(), "", &mut state)
            .await?;

        Ok(state)
    }

    /// Recursively load state from the Merkle index tree.
    async fn load_state_from_index(
        &self,
        index_id: akshara_aadhaara::BlockId,
        prefix: &str,
        state: &mut BTreeMap<String, (StateValue, akshara_aadhaara::BlockId)>,
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

        let index_map: BTreeMap<String, akshara_aadhaara::Address> =
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
                        state.insert(full_path, (StateValue::Data(data), block_id));
                    }
                }
            }
        }

        Ok(())
    }
}
