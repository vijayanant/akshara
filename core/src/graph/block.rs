use crate::crypto::{BlockContent, GraphKey, Signature, SigningPublicKey, SovereignSigner};
use crate::error::{CryptoError, IntegrityError, SovereignError};
use crate::graph::BlockId;
use cid::Cid;
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::{Level, info, span};

/// A `Block` is the atomic unit of content in Sovereign.
///
/// It is immutable, content-addressed, and cryptographically signed.
/// All blocks are encrypted with the GraphKey before being hashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// The unique identifier of the block (CIDv1).
    id: BlockId,
    /// The public key of the user who authored this block.
    author: SigningPublicKey,
    /// An Ed25519 signature over the `id`.
    signature: Signature,
    /// The encrypted payload (text, image data, or a serialized Index Map).
    content: BlockContent,
    /// A hint for the application layer on how to render this block (e.g., "p", "index").
    block_type: String,
    /// References to the block IDs that this block replaces or merges.
    parents: Vec<BlockId>,
}

impl Block {
    /// Creates and signs a new Data Block.
    pub fn new(
        plaintext: Vec<u8>,
        block_type: String,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl SovereignSigner,
    ) -> Result<Self, SovereignError> {
        let nonce = [0u8; 12]; // TODO: Real randomness
        let content = BlockContent::encrypt(&plaintext, key, nonce)?;

        Ok(Self::create(content, block_type, parents, signer))
    }

    /// Creates and signs a new Index Block.
    ///
    /// The index is a map of names to CIDs. It is serialized using CBOR
    /// to ensure canonical byte ordering before encryption.
    pub fn new_index(
        index: BTreeMap<String, Cid>,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl SovereignSigner,
    ) -> Result<Self, SovereignError> {
        let plaintext = serde_cbor::to_vec(&index).map_err(|e| {
            SovereignError::InternalError(format!("CBOR serialization failed: {}", e))
        })?;

        let nonce = [0u8; 12]; // TODO: Real randomness
        let content = BlockContent::encrypt(&plaintext, key, nonce)?;

        Ok(Self::create(content, "index".to_string(), parents, signer))
    }

    /// Internal factory to handle ID calculation and signing.
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

    /// Restores a Block from its raw components.
    pub fn from_raw_parts(
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

    /// Validates the internal consistency of the block.
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

    /// Computes the canonical CID of the block's data.
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
