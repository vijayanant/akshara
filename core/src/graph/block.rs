use crate::crypto::{BlockContent, Signature, SigningPublicKey};
use crate::graph::BlockId;
use crate::identity::SecretIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    id: BlockId,
    author: SigningPublicKey,
    signature: Signature,
    content: BlockContent,
    rank: String,
    block_type: String,
    parents: Vec<BlockId>,
}

impl Block {
    pub fn new(
        content: BlockContent,
        rank: String,
        block_type: String,
        parents: Vec<BlockId>,
        identity: &SecretIdentity,
    ) -> Self {
        // Pure construction: Calculate ID first
        let id = Self::compute_id(&content, &rank, &block_type, &parents);

        // Then sign
        let signature = identity.sign(id.as_ref());

        // Then construct immutable struct
        Block {
            id,
            author: identity.public().signing_key().clone(),
            signature,
            content,
            rank,
            block_type,
            parents,
        }
    }

    pub fn id(&self) -> BlockId {
        self.id
    }

    pub fn author(&self) -> &SigningPublicKey {
        &self.author
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn content(&self) -> &BlockContent {
        &self.content
    }

    pub fn rank(&self) -> &str {
        &self.rank
    }

    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    pub fn verify_integrity(&self) -> Result<(), String> {
        // 1. Check if ID matches content
        let calculated_id =
            Self::compute_id(&self.content, &self.rank, &self.block_type, &self.parents);
        if self.id != calculated_id {
            return Err(format!(
                "Block ID mismatch: stored {:?}, calculated {:?}",
                self.id, calculated_id
            ));
        }

        // 2. Check signature
        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    // Pure function for ID calculation (Static method)
    fn compute_id(
        content: &BlockContent,
        rank: &str,
        block_type: &str,
        parents: &[BlockId],
    ) -> BlockId {
        let mut hasher = Sha256::new();
        hasher.update(b"BLOCK_V1");

        hasher.update(content.as_bytes());
        hasher.update(content.nonce());
        hasher.update(rank.as_bytes());
        hasher.update(block_type.as_bytes());

        for parent in parents {
            hasher.update(parent.as_ref());
        }

        BlockId(hasher.finalize().into())
    }
}
