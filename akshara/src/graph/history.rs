use chrono::{DateTime, Utc};

use akshara_aadhaara::{Block, BlockId, GraphStore, ManifestId, Signature, SigningPublicKey};
use crate::error::{Error, Result};
use super::{validate_path_read, Graph};

#[cfg(feature = "schema")]
use crate::schema::AksharaDocument;

/// A single revision entry in the raw history trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionEntry {
    /// The decrypted raw bytes of this revision.
    pub value: Vec<u8>,
    /// The Block ID (CID) of this revision.
    pub block_id: BlockId,
    /// The Manifest ID anchoring this revision.
    pub manifest_id: ManifestId,
    /// The author signature attesting to this revision.
    pub signature: Signature,
    /// The author public key.
    pub author: SigningPublicKey,
    /// When this revision was committed.
    pub timestamp: DateTime<Utc>,
}

/// A typed version of a document in the historical edit trail.
#[cfg(feature = "schema")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentVersion<T> {
    /// The deserialized value of the document.
    pub value: T,
    /// The Block ID (CID) of this version.
    pub block_id: BlockId,
    /// The Manifest ID anchoring this version.
    pub manifest_id: ManifestId,
    /// When this version was committed.
    pub authored_at: DateTime<Utc>,
    /// Human-readable fingerprint of the author's public identity.
    pub author_fingerprint: String,
}

impl Graph {
    /// Retrieve the complete raw change history for a specific path or field.
    ///
    /// This walks the manifest chain backward from the current head, resolving the path
    /// at each manifest checkpoint to identify block modifications, signatures, and timestamps.
    pub async fn get_history(&self, path: &str) -> Result<Vec<RevisionEntry>> {
        validate_path_read(path)?;
        let heads = self
            .store
            .get_heads(&self.graph_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get heads: {}", e)))?;

        if heads.is_empty() {
            return Ok(Vec::new());
        }

        let mut revisions = Vec::new();
        let mut current_manifest_id = heads[0];
        let mut visited_manifests = std::collections::HashSet::new();

        while current_manifest_id != ManifestId::null() {
            if !visited_manifests.insert(current_manifest_id) {
                break;
            }

            let manifest = match self.store.get_manifest(&current_manifest_id).await {
                Ok(Some(m)) => m,
                _ => break,
            };

            let walker = akshara_aadhaara::GraphWalker::new(&self.store);
            let address_result = walker
                .resolve_path(
                    &self.graph_id,
                    manifest.content_root(),
                    path,
                    &self.graph_key,
                )
                .await;

            let block_id_opt = address_result
                .ok()
                .and_then(|addr| BlockId::try_from(addr).ok());

            if let Some(block_id) = block_id_opt {
                // To support updates & deduplicate contiguous duplicates, check against last recorded entry
                let is_duplicate = revisions
                    .last()
                    .map(|last: &RevisionEntry| last.block_id == block_id)
                    .unwrap_or(false);

                if !is_duplicate {
                    if let Some((block, content)) = self.decrypt_block_at(&block_id).await {
                        revisions.push(RevisionEntry {
                            value: content,
                            block_id,
                            manifest_id: current_manifest_id,
                            signature: block.signature().clone(),
                            author: block.author().clone(),
                            timestamp: DateTime::<Utc>::from_timestamp(manifest.created_at(), 0).unwrap_or_default(),
                        });
                    }
                }
            }

            // Move to parent manifest
            current_manifest_id = if !manifest.parents().is_empty() {
                manifest.parents()[0]
            } else {
                ManifestId::null()
            };
        }

        // Return chronological order (oldest first)
        revisions.reverse();
        Ok(revisions)
    }

    /// Retrieve and decrypt a block, satisfying lints.
    async fn decrypt_block_at(&self, block_id: &BlockId) -> Option<(Block, Vec<u8>)> {
        let block = self.store.get_block(block_id).await.ok().flatten()?;
        let content = block.decrypt(&self.graph_id, &self.graph_key).ok()?;
        Some((block, content))
    }

    /// Walk the full manifest history to get all versions of a document.
    #[cfg(feature = "schema")]
    pub async fn history<T>(&self, path: &str) -> Result<Vec<DocumentVersion<T>>>
    where
        T: AksharaDocument,
    {
        let doc_internal_path = format!("{}/.akshara.document", path);
        let raw_history = self.get_history(&doc_internal_path).await?;
        let mut versions = Vec::new();

        for entry in raw_history {
            let value = akshara_aadhaara::from_canonical_bytes(&entry.value).map_err(|e| {
                Error::Internal(format!("Failed to deserialize history entry: {}", e))
            })?;

            let author_fingerprint = hex::encode(&entry.author.as_bytes()[0..8]);

            versions.push(DocumentVersion {
                value,
                block_id: entry.block_id,
                manifest_id: entry.manifest_id,
                authored_at: entry.timestamp,
                author_fingerprint,
            });
        }

        Ok(versions)
    }
}
