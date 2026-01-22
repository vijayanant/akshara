use crate::crypto::{Signature, SigningPublicKey};
use crate::graph::{BlockId, ManifestId};
use crate::identity::SecretIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    id: ManifestId,
    document_id: Uuid,
    parents: Vec<ManifestId>,
    active_blocks: Vec<BlockId>,
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
        let mut manifest = Manifest {
            id: ManifestId([0; 32]),
            document_id,
            parents,
            active_blocks,
            author: identity.public().signing_key().clone(),
            signature: Signature::new(vec![]),
            created_at: 0,
        };
        manifest.id = manifest.calculate_merkle_root();
        manifest.signature = identity.sign(manifest.id.as_ref());
        manifest
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

    fn calculate_merkle_root(&self) -> ManifestId {
        if self.active_blocks.is_empty() {
            return ManifestId([0; 32]);
        }

        let mut nodes: Vec<[u8; 32]> = self.active_blocks.iter().map(|b| b.0).collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in nodes.chunks(2) {
                let mut hasher = Sha256::new();
                // LLD-002: Domain Separation
                hasher.update(b"SOV_V2_NODE");
                hasher.update(chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(chunk[1]);
                } else {
                    hasher.update(chunk[0]); // Duplicate last if odd
                }
                next_level.push(hasher.finalize().into());
            }
            nodes = next_level;
        }

        ManifestId(nodes[0])
    }
}
