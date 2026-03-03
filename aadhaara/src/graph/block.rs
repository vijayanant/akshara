use crate::base::address::BlockId;
use crate::base::crypto::{BlockContent, GraphKey, Signature, SigningPublicKey, SovereignSigner};
use crate::base::error::{CryptoError, IntegrityError, SovereignError};
use cid::Cid;
use metrics::counter;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::{Level, info, span};

/// A `Block` is the atomic unit of content in Sovereign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub(crate) id: BlockId,
    pub(crate) author: SigningPublicKey,
    pub(crate) signature: Signature,
    pub(crate) content: BlockContent,
    pub(crate) block_type: String,
    pub(crate) parents: Vec<BlockId>,
}

impl Block {
    pub fn new(
        plaintext: Vec<u8>,
        block_type: String,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl SovereignSigner,
    ) -> Result<Self, SovereignError> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let content = BlockContent::encrypt(&plaintext, key, nonce)?;

        Ok(Self::create(content, block_type, parents, signer))
    }

    pub fn new_index(
        index: BTreeMap<String, Cid>,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl SovereignSigner,
    ) -> Result<Self, SovereignError> {
        let plaintext = serde_ipld_dagcbor::to_vec(&index).map_err(|e| {
            SovereignError::InternalError(format!("DAG-CBOR serialization failed: {}", e))
        })?;

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let content = BlockContent::encrypt(&plaintext, key, nonce)?;

        Ok(Self::create(content, "index".to_string(), parents, signer))
    }

    fn create(
        content: BlockContent,
        block_type: String,
        parents: Vec<BlockId>,
        signer: &impl SovereignSigner,
    ) -> Self {
        let id = Self::compute_id(&content, &block_type, &parents);
        let signature = signer.sign(id.as_ref());

        info!(block_id = ?id, "Block created");
        counter!("sovereign.block.created").increment(1);

        Block {
            id,
            author: signer.public_key(),
            signature,
            content,
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

    pub fn block_type(&self) -> &str {
        &self.block_type
    }

    pub fn parents(&self) -> &[BlockId] {
        &self.parents
    }

    /// Public-Crate API: Used by sibling crates for wire mapping.
    #[allow(dead_code)]
    pub(crate) fn from_raw_parts(
        id: BlockId,
        author: SigningPublicKey,
        signature: Signature,
        content: BlockContent,
        block_type: String,
        parents: Vec<BlockId>,
    ) -> Self {
        Self {
            id,
            author,
            signature,
            content,
            block_type,
            parents,
        }
    }

    pub fn verify_integrity(&self) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "block_verify_integrity", block_id = ?self.id);
        let _enter = span.enter();

        let calculated_id = Self::compute_id(&self.content, &self.block_type, &self.parents);
        if self.id != calculated_id {
            return Err(SovereignError::Integrity(IntegrityError::BlockIdMismatch(
                self.id,
            )));
        }

        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| SovereignError::Crypto(CryptoError::InvalidSignature(e.to_string())))?;

        Ok(())
    }

    fn compute_id(content: &BlockContent, block_type: &str, parents: &[BlockId]) -> BlockId {
        let mut hasher = Sha256::new();
        hasher.update(b"SOV_V1_BLOCK");
        hasher.update(content.as_bytes());
        hasher.update(content.nonce());
        hasher.update(block_type.as_bytes());

        for parent in parents {
            hasher.update(parent.as_ref());
        }

        BlockId::from_sha256(&hasher.finalize())
    }
}
