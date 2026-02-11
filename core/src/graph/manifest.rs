use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{Level, info, span};

use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{Signature, SigningPublicKey, SovereignSigner};
use crate::base::error::{CryptoError, IntegrityError, SovereignError};

/// A `Manifest` is a signed snapshot of a graph's state.
///
/// It points to a single `content_root` (the top-level Index Block), forming
/// a Merkle Tree. This ensures that the Manifest size remains constant regardless
/// of the number of blocks in the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// The unique identifier of this snapshot (CIDv1).
    id: ManifestId,
    /// The unique ID of the graph this manifest belongs to.
    graph_id: GraphId,
    /// The CID of the root Index Block (the top of the Merkle Tree).
    content_root: BlockId,
    /// References to the manifest(s) that immediately preceded this one.
    parents: Vec<ManifestId>,
    /// CID of the author's current Identity Manifest (The Authority Anchor).
    identity_anchor: ManifestId,
    /// The public key of the user who published this snapshot.
    author: SigningPublicKey,
    /// A signature over the `id`.
    signature: Signature,
    /// Unix timestamp of creation.
    created_at: i64,
}

impl Manifest {
    /// Creates and signs a new manifest snapshot using the Merkle Index model.
    pub fn new(
        graph_id: GraphId,
        content_root: BlockId,
        parents: Vec<ManifestId>,
        identity_anchor: ManifestId,
        signer: &impl SovereignSigner,
    ) -> Self {
        let span = span!(Level::INFO, "manifest_new", graph_id = ?graph_id);
        let _enter = span.enter();

        let created_at = 0; // TODO: Real system time
        let author = signer.public_key();

        let id = Self::compute_id(
            &graph_id,
            &content_root,
            &parents,
            &identity_anchor,
            &author,
            created_at,
        );

        let signature = signer.sign(id.as_ref());

        info!(manifest_id = ?id, "Manifest created");
        counter!("sovereign.manifest.created").increment(1);

        Manifest {
            id,
            graph_id,
            content_root,
            parents,
            identity_anchor,
            author,
            signature,
            created_at,
        }
    }

    pub fn id(&self) -> ManifestId {
        self.id
    }

    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    pub fn content_root(&self) -> BlockId {
        self.content_root
    }

    pub fn parents(&self) -> &[ManifestId] {
        &self.parents
    }

    pub fn identity_anchor(&self) -> ManifestId {
        self.identity_anchor
    }

    pub fn author(&self) -> &SigningPublicKey {
        &self.author
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Restores a Manifest from raw components.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        id: ManifestId,
        graph_id: GraphId,
        content_root: BlockId,
        parents: Vec<ManifestId>,
        identity_anchor: ManifestId,
        author: SigningPublicKey,
        signature: Signature,
        created_at: i64,
    ) -> Self {
        Self {
            id,
            graph_id,
            content_root,
            parents,
            identity_anchor,
            author,
            signature,
            created_at,
        }
    }

    /// Verifies the cryptographic integrity of the manifest.
    pub fn verify_integrity(&self) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "manifest_verify_integrity", manifest_id = ?self.id);
        let _enter = span.enter();

        // 1. Re-calculate ID
        let calculated_id = Self::compute_id(
            &self.graph_id,
            &self.content_root,
            &self.parents,
            &self.identity_anchor,
            &self.author,
            self.created_at,
        );
        if self.id != calculated_id {
            return Err(SovereignError::Integrity(
                IntegrityError::ManifestIdMismatch(self.id),
            ));
        }

        // 2. Verify signature
        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| SovereignError::Crypto(CryptoError::InvalidSignature(e.to_string())))?;

        Ok(())
    }

    /// Canonical hash function for the manifest's identity.
    fn compute_id(
        graph_id: &GraphId,
        content_root: &BlockId,
        parents: &[ManifestId],
        identity_anchor: &ManifestId,
        author: &SigningPublicKey,
        created_at: i64,
    ) -> ManifestId {
        let mut hasher = Sha256::new();
        hasher.update(b"SOV_V1_MANIFEST");
        hasher.update(graph_id.0.as_bytes());
        hasher.update(content_root.as_ref());
        for p in parents {
            hasher.update(p.as_ref());
        }
        hasher.update(identity_anchor.as_ref());
        hasher.update(author.as_bytes());
        hasher.update(created_at.to_le_bytes());

        ManifestId::from_sha256(&hasher.finalize())
    }
}
