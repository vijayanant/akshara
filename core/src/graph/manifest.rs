use crate::crypto::{Signature, SigningPublicKey};
use crate::graph::{BlockId, ManifestId};
use crate::identity::SecretIdentity;
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{Level, info, span};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    id: ManifestId,
    document_id: Uuid,
    parents: Vec<ManifestId>,
    active_blocks: Vec<BlockId>,
    merkle_root: ManifestId,
    author: SigningPublicKey,
    signature: Signature,
    created_at: i64,
}

impl Manifest {
    pub fn new(
        document_id: Uuid,
        active_blocks: Vec<BlockId>,
        parents: Vec<ManifestId>,
        identity: &SecretIdentity,
    ) -> Self {
        let span = span!(Level::INFO, "manifest_new", document_id = %document_id);
        let _enter = span.enter();

        let merkle_root = Self::compute_merkle_root(&active_blocks);
        let created_at = 0; // Fixed for now, pass as arg later
        let author = identity.public().signing_key().clone();

        let id = Self::compute_id(&merkle_root, &document_id, &parents, &author, created_at);

        let signature = identity.sign(id.as_ref());

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
