use crate::crypto::{Signature, SigningPublicKey, SovereignSigner};
use crate::error::SovereignError;
use crate::graph::{BlockId, ManifestId};
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tracing::{Level, info, span};
use uuid::Uuid;

/// A `Manifest` is a snapshot of the document's state at a specific point in history.
///
/// It acts like a "commit" in a version control system, grouping a set of `active_blocks`
/// into a coherent version. The integrity of the blocks is guaranteed by a Merkle Root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// The unique identifier of this snapshot. Hashes the Merkle root, parents,
    /// and metadata to bind the state to its specific historical context.
    id: ManifestId,
    /// The unique ID of the document (the entire DAG) this manifest belongs to.
    document_id: Uuid,
    /// References to the manifest(s) that immediately preceded this one.
    parents: Vec<ManifestId>,
    /// The complete, ordered set of blocks that make up this version of the document.
    active_blocks: Vec<BlockId>,
    /// The root of a Merkle Tree built from `active_blocks`, providing a compact
    /// proof of the document's entire content.
    merkle_root: ManifestId,
    /// The public key of the user who published this state snapshot.
    author: SigningPublicKey,
    /// A signature over the `id`, proving the author intended to publish this state.
    signature: Signature,
    /// Unix timestamp of creation (local to the author).
    created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestDiff {
    pub left_only: Vec<BlockId>,
    pub right_only: Vec<BlockId>,
    pub shared: Vec<BlockId>,
}

impl Manifest {
    /// Creates and signs a new manifest snapshot.
    ///
    /// Accepts any `SovereignSigner`, allowing for hardware wallets or remote signers.
    pub fn new(
        document_id: Uuid,
        active_blocks: Vec<BlockId>,
        parents: Vec<ManifestId>,
        signer: &impl SovereignSigner,
    ) -> Self {
        let span = span!(Level::INFO, "manifest_new", document_id = %document_id);
        let _enter = span.enter();

        let merkle_root = Self::compute_merkle_root(&active_blocks);
        let created_at = 0; // TODO: Integrate real system time
        let author = signer.public_key();

        let id = Self::compute_id(&merkle_root, &document_id, &parents, &author, created_at);

        let signature = signer.sign(id.as_ref());

        info!(manifest_id = ?id, "Manifest created");
        counter!("sovereign.manifest.created").increment(1);

        Manifest {
            id,
            document_id,
            parents,
            active_blocks,
            merkle_root,
            author,
            signature,
            created_at,
        }
    }

    pub fn id(&self) -> ManifestId {
        self.id
    }

    pub fn document_id(&self) -> Uuid {
        self.document_id
    }

    pub fn active_blocks(&self) -> &Vec<BlockId> {
        &self.active_blocks
    }

    pub fn parents(&self) -> &Vec<ManifestId> {
        &self.parents
    }

    pub fn author(&self) -> &SigningPublicKey {
        &self.author
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn merkle_root(&self) -> ManifestId {
        self.merkle_root
    }

    /// Verifies the cryptographic integrity of the manifest.
    ///
    /// Ensures that:
    /// 1. The Merkle root correctly represents the `active_blocks`.
    /// 2. The `id` correctly represents the manifest's metadata and history.
    /// 3. The `signature` is valid for the `id`.
    pub fn verify_integrity(&self) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "manifest_verify_integrity", manifest_id = ?self.id);
        let _enter = span.enter();

        // 1. Re-calculate Merkle Root
        let calculated_root = Self::compute_merkle_root(&self.active_blocks);
        if self.merkle_root != calculated_root {
            return Err(SovereignError::ManifestMerkleMismatch(self.id));
        }

        // 2. Re-calculate ID
        let calculated_id = Self::compute_id(
            &self.merkle_root,
            &self.document_id,
            &self.parents,
            &self.author,
            self.created_at,
        );
        if self.id != calculated_id {
            return Err(SovereignError::Unauthorized(
                "Manifest ID mismatch".to_string(),
            ));
        }

        // 3. Verify signature
        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| SovereignError::SignatureFailure(e.to_string()))?;

        Ok(())
    }

    /// Calculates the difference between this manifest (Left) and another (Right).
    ///
    /// Returns a `ManifestDiff` struct containing blocks exclusive to each side and shared blocks.
    /// This is the foundation for 3-way merge logic.
    pub fn diff(&self, right: &Manifest, _base: Option<&Manifest>) -> ManifestDiff {
        let left_set: HashSet<_> = self.active_blocks.iter().cloned().collect();
        let right_set: HashSet<_> = right.active_blocks.iter().cloned().collect();

        let left_only: Vec<_> = left_set.difference(&right_set).cloned().collect();
        let right_only: Vec<_> = right_set.difference(&left_set).cloned().collect();
        let shared: Vec<_> = left_set.intersection(&right_set).cloned().collect();

        ManifestDiff {
            left_only,
            right_only,
            shared,
        }
    }

    /// Computes a Merkle Root from a list of block IDs using pairwise recursive hashing.
    fn compute_merkle_root(active_blocks: &[BlockId]) -> ManifestId {
        if active_blocks.is_empty() {
            return ManifestId([0; 32]);
        }

        let mut nodes: Vec<[u8; 32]> = active_blocks.iter().map(|b| b.0).collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in nodes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(b"SOV_V2_NODE");
                hasher.update(chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(chunk[1]);
                } else {
                    hasher.update(chunk[0]);
                }
                next_level.push(hasher.finalize().into());
            }
            nodes = next_level;
        }

        ManifestId(nodes[0])
    }

    /// Canonical hash function for the manifest's identity.
    fn compute_id(
        merkle_root: &ManifestId,
        document_id: &Uuid,
        parents: &[ManifestId],
        author: &SigningPublicKey,
        created_at: i64,
    ) -> ManifestId {
        let mut hasher = Sha256::new();
        hasher.update(b"SOV_V2_MANIFEST");
        hasher.update(merkle_root.as_ref());
        hasher.update(document_id.as_bytes());
        for p in parents {
            hasher.update(p.as_ref());
        }
        hasher.update(author.as_bytes());
        hasher.update(created_at.to_le_bytes());

        ManifestId(hasher.finalize().into())
    }
}
