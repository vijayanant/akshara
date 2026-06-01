use akshara_aadhaara::GraphStore;
use crate::error::{Error, Result};
use crate::staging::{StagedOperation, StagingStore};
use super::{current_timestamp, validate_path, validate_path_read, Graph};

impl Graph {
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
        validate_path_read(path)?;
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
                Error::PathNotFound(format!("Path not found '{}': {}", path, e))
            })?;

        let block_id = akshara_aadhaara::BlockId::try_from(address)
            .map_err(|e| Error::Internal(format!("Invalid block id: {}", e)))?;

        let block = self
            .store
            .get_block(&block_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| Error::PathNotFound(format!("Block not found: {}", block_id)))?;

        let content = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        Ok(content)
    }

    /// Fetch raw binary blob payload at the specified path.
    pub async fn fetch_blob(&self, path: &str) -> Result<Vec<u8>> {
        self.get(path).await
    }

    /// Returns the BlockId (CID) for the specified path.
    pub async fn get_id(&self, path: &str) -> Result<akshara_aadhaara::BlockId> {
        validate_path_read(path)?;
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
        if !prefix.is_empty() {
            validate_path_read(prefix)?;
        }
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
}
