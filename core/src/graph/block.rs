use crate::identity::SecretIdentity;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Block {
    id: [u8; 32],
    author_key: [u8; 32],
    signature: [u8; 64],
    encrypted_data: Vec<u8>,
    nonce: [u8; 12],
    rank: String,
    block_type: String,
    parents: Vec<[u8; 32]>,
}

impl Block {
    pub fn new(
        encrypted_data: Vec<u8>,
        nonce: [u8; 12],
        rank: String,
        block_type: String,
        parents: Vec<[u8; 32]>,
        identity: &SecretIdentity,
    ) -> Self {
        let mut block = Block {
            id: [0; 32],
            author_key: identity.public().signing_key(),
            signature: [0; 64],
            encrypted_data,
            nonce,
            rank,
            block_type,
            parents,
        };
        block.id = block.calculate_id();
        block.signature = identity.sign(&block.id);
        block
    }

    pub fn new_encrypted(
        plaintext: Vec<u8>,
        rank: String,
        block_type: String,
        parents: Vec<[u8; 32]>,
        identity: &SecretIdentity,
        doc_key: &[u8; 32],
    ) -> Self {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new(doc_key.into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_data = cipher
            .encrypt(nonce, plaintext.as_slice())
            .expect("Encryption failed");

        Self::new(
            encrypted_data,
            nonce_bytes,
            rank,
            block_type,
            parents,
            identity,
        )
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

    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn rank(&self) -> &str {
        &self.rank
    }

    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    pub fn decrypt(&self, doc_key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(doc_key.into());
        let nonce = Nonce::from_slice(&self.nonce);
        cipher
            .decrypt(nonce, self.encrypted_data.as_slice())
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BLOCK_V1");

        hasher.update(&self.encrypted_data);
        hasher.update(self.nonce);
        hasher.update(self.rank.as_bytes());
        hasher.update(self.block_type.as_bytes());

        for parent in &self.parents {
            hasher.update(parent);
        }

        hasher.finalize().into()
    }
}
