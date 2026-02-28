use crate::base::address::{BlockId, GraphId, ManifestId};
use crate::base::crypto::{Signature, SigningPublicKey, SovereignSigner};
use crate::base::error::{CryptoError, IntegrityError, SovereignError};
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Level, info, span};

/// Represents the historical and structural metadata of a graph snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub(crate) graph_id: GraphId,
    pub(crate) content_root: BlockId,
    pub(crate) parents: Vec<ManifestId>,
    pub(crate) identity_anchor: ManifestId,
    pub(crate) signer_path: String,
    pub(crate) created_at: i64,
}

/// A `Manifest` is a signed snapshot of a graph's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub(crate) id: ManifestId,
    pub(crate) header: ManifestHeader,
    pub(crate) author: SigningPublicKey,
    pub(crate) signature: Signature,
}

impl Manifest {
    pub fn new(
        graph_id: GraphId,
        content_root: BlockId,
        parents: Vec<ManifestId>,
        identity_anchor: ManifestId,
        signer: &impl SovereignSigner,
    ) -> Self {
        let span = span!(Level::INFO, "manifest_new", graph_id = ?graph_id);
        let _enter = span.enter();

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let header = ManifestHeader {
            graph_id,
            content_root,
            parents,
            identity_anchor,
            signer_path: signer.derivation_path().to_string(),
            created_at,
        };

        let id = Self::compute_id(&header, &signer.public_key());
        let signature = signer.sign(id.as_ref());

        info!(manifest_id = ?id, "Manifest created");
        counter!("sovereign.manifest.created").increment(1);

        Manifest {
            id,
            header,
            author: signer.public_key(),
            signature,
        }
    }

    pub fn id(&self) -> ManifestId {
        self.id
    }

    pub fn graph_id(&self) -> GraphId {
        self.header.graph_id
    }

    pub fn content_root(&self) -> BlockId {
        self.header.content_root
    }

    pub fn parents(&self) -> &[ManifestId] {
        &self.header.parents
    }

    pub fn identity_anchor(&self) -> ManifestId {
        self.header.identity_anchor
    }

    pub fn author(&self) -> &SigningPublicKey {
        &self.author
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn created_at(&self) -> i64 {
        self.header.created_at
    }

    pub fn signer_path(&self) -> &str {
        &self.header.signer_path
    }

    /// Public-Crate API: Used by sibling crates for wire mapping.
    #[allow(dead_code)]
    pub(crate) fn from_raw_parts(
        id: ManifestId,
        header: ManifestHeader,
        author: SigningPublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            id,
            header,
            author,
            signature,
        }
    }

    pub fn verify_integrity(&self) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "manifest_verify_integrity", manifest_id = ?self.id);
        let _enter = span.enter();

        let calculated_id = Self::compute_id(&self.header, &self.author);
        if self.id != calculated_id {
            return Err(SovereignError::Integrity(
                IntegrityError::ManifestIdMismatch(self.id),
            ));
        }

        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| SovereignError::Crypto(CryptoError::InvalidSignature(e.to_string())))?;

        Ok(())
    }

    fn compute_id(header: &ManifestHeader, author: &SigningPublicKey) -> ManifestId {
        let mut hasher = Sha256::new();
        hasher.update(b"SOV_V1_MANIFEST");
        hasher.update(header.graph_id.as_bytes());
        hasher.update(header.content_root.as_ref());
        for p in &header.parents {
            hasher.update(p.as_ref());
        }
        hasher.update(header.identity_anchor.as_ref());
        hasher.update(author.as_bytes());
        hasher.update(header.signer_path.as_bytes());
        hasher.update(header.created_at.to_le_bytes());

        ManifestId::from_sha256(&hasher.finalize())
    }
}
