use crate::crypto::{BlockContent, Signature, SigningPublicKey};
use crate::graph::BlockId;
use crate::identity::SecretIdentity;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
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
        // Placeholder ID until calculated
        let mut block = Block {
            id: BlockId([0; 32]),
            author: identity.public().signing_key().clone(),
            signature: Signature::new(vec![]),
            content,
            rank,
            block_type,
            parents,
        };
        block.id = block.calculate_id();
        block.signature = identity.sign(block.id.as_ref());
        block
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

    fn calculate_id(&self) -> BlockId {
        let mut hasher = Sha256::new();
        hasher.update(b"BLOCK_V1");

        hasher.update(self.content.as_bytes());
        hasher.update(self.content.nonce());
        hasher.update(self.rank.as_bytes());
        hasher.update(self.block_type.as_bytes());

        for parent in &self.parents {
            hasher.update(parent.as_ref());
        }

        BlockId(hasher.finalize().into())
    }
}
