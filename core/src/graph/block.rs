use crate::identity::SecretIdentity;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Block {
    id: [u8; 32],
    author_key: [u8; 32],
    signature: [u8; 64],
    content: Vec<u8>,
    rank: String,
    block_type: String,
    parents: Vec<[u8; 32]>,
}

impl Block {
    pub fn new(
        content: Vec<u8>,
        rank: String,
        block_type: String,
        parents: Vec<[u8; 32]>,
        identity: &SecretIdentity,
    ) -> Self {
        let mut block = Block {
            id: [0; 32],
            author_key: identity.public().signing_key(),
            signature: [0; 64],
            content,
            rank,
            block_type,
            parents,
        };
        block.id = block.calculate_id();
        block.signature = identity.sign(&block.id);
        block
    }

    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub fn author_key(&self) -> [u8; 32] {
        self.author_key
    }

    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn rank(&self) -> &str {
        &self.rank
    }

    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BLOCK_V1");

        hasher.update(&self.content);
        hasher.update(self.rank.as_bytes());
        hasher.update(self.block_type.as_bytes());

        for parent in &self.parents {
            hasher.update(parent);
        }

        hasher.finalize().into()
    }
}
