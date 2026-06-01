use super::{Graph, current_timestamp, validate_path};
use crate::error::{Error, Result};
use crate::schema::AksharaDocument;
use crate::staging::{StagedOperation, StagingStore};
use akshara_aadhaara::GraphStore;

impl Graph {
    /// Insert a typed document at the specified path.
    pub async fn insert_document<D: AksharaDocument>(&self, path: &str, doc: &D) -> Result<()> {
        validate_path(path)?;

        // 1. Serialize the main document struct
        let doc_bytes = doc
            .to_bytes()
            .map_err(|e| Error::Internal(format!("Failed to serialize document: {}", e)))?;

        let doc_internal_path = format!("{}/.akshara.document", path);
        let op = StagedOperation::Insert {
            path: doc_internal_path,
            data: doc_bytes,
            timestamp: current_timestamp(),
        };
        self.staging.stage_operation(op).await?;

        // 2. Serialize and stage the schema metadata
        let schema = D::schema();
        let schema_bytes = akshara_aadhaara::to_canonical_bytes(&schema)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {}", e)))?;

        let schema_path = format!("{}/.akshara.schema", path);
        let schema_op = StagedOperation::Insert {
            path: schema_path,
            data: schema_bytes,
            timestamp: current_timestamp(),
        };
        self.staging.stage_operation(schema_op).await?;

        // 3. Serialize all fields requiring block layouts
        let identity = self.vault.get_identity(Some(&self.graph_id)).await?;
        let field_links = doc
            .serialize_fields(
                &self.graph_id,
                &self.graph_key,
                &identity,
                &self.store,
                path,
            )
            .await
            .map_err(|e| Error::Internal(format!("Field serialization failed: {}", e)))?;

        // 4. Stage Link operations for each field resolved address
        for (field_rel_path, address) in field_links {
            let field_path = format!("{}/{}", path, field_rel_path);
            let link_op = StagedOperation::Link {
                path: field_path,
                address,
                timestamp: current_timestamp(),
            };
            self.staging.stage_operation(link_op).await?;
        }

        Ok(())
    }

    /// Retrieve and reassemble a typed document from the specified path.
    pub async fn get_document<D: AksharaDocument>(&self, path: &str) -> Result<D> {
        validate_path(path)?;

        // 1. Locate the latest manifest content root to resolve field CIDs
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Err(Error::PathNotFound(format!(
                "No manifest sealed yet for document path: {}",
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

        // 2. Fetch and deserialize the main document root block from doc_path/.akshara.document
        let doc_internal_path = format!("{}/.akshara.document", path);
        let walker = akshara_aadhaara::GraphWalker::new(&self.store);
        let doc_address = walker
            .resolve_path(
                &self.graph_id,
                manifest.content_root(),
                &doc_internal_path,
                &self.graph_key,
            )
            .await
            .map_err(|e| {
                Error::PathNotFound(format!(
                    "Document not found at '{}': {}",
                    doc_internal_path, e
                ))
            })?;

        let block_id = akshara_aadhaara::BlockId::try_from(doc_address)
            .map_err(|e| Error::Internal(format!("Invalid block id: {}", e)))?;

        let block = self
            .store
            .get_block(&block_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| Error::PathNotFound(format!("Block not found: {}", block_id)))?;

        let main_bytes = block
            .decrypt(&self.graph_id, &self.graph_key)
            .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;

        let mut doc = D::from_bytes(&main_bytes)
            .map_err(|e| Error::Internal(format!("Failed to deserialize document: {}", e)))?;

        // 3. Reassemble all layout fields using the manifest content root
        doc.deserialize_fields(
            &self.graph_id,
            &self.graph_key,
            &self.store,
            path,
            &manifest.content_root(),
        )
        .await
        .map_err(|e| Error::Internal(format!("Field deserialization failed: {}", e)))?;

        Ok(doc)
    }
}
