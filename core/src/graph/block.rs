use crate::crypto::{BlockContent, Signature, SigningPublicKey, SovereignSigner};
use crate::error::SovereignError;
use crate::graph::BlockId;
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{Level, info, span};

/// A `Block` is the atomic unit of content in Sovereign.
///
/// It is immutable, content-addressed, and cryptographically signed.
/// Blocks form a Directed Acyclic Graph (DAG) where each block can
/// reference previous versions via the `parents` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// The unique identifier of the block, calculated as the SHA-256 hash
    /// of its content and metadata. This ensures content-addressing.
    id: BlockId,
    /// The public key of the user who authored this block.
    author: SigningPublicKey,
    /// An Ed25519 signature over the `id`, proving authenticity and intent.
    signature: Signature,
    /// The encrypted payload (text, image data, etc.) and its nonce.
    content: BlockContent,
    /// A fractional index used for conflict-free lexicographical ordering
    /// of blocks within a document.
    rank: String,
    /// A hint for the application layer on how to render this block (e.g., "p", "h1").
    block_type: String,
    /// References to the block IDs that this block replaces or merges.
    parents: Vec<BlockId>,
}

impl Block {
    /// Creates and signs a new block.
    ///
    /// This constructor performs "pure construction" by calculating the
    /// content-address (ID) and signature before initializing the struct,
    /// ensuring that a `Block` instance is always valid from birth.
    ///
    /// Accepts any `SovereignSigner`, allowing for hardware wallets or remote signers.
    pub fn new(
        content: BlockContent,
        rank: String,
        block_type: String,
        parents: Vec<BlockId>,
        signer: &impl SovereignSigner,
    ) -> Self {
        let span = span!(Level::INFO, "block_new", rank = %rank, block_type = %block_type);
        let _enter = span.enter();

        let id = Self::compute_id(&content, &rank, &block_type, &parents);
        let signature = signer.sign(id.as_ref());

        info!(block_id = ?id, "Block created");
        counter!("sovereign.block.created").increment(1);

        Block {
            id,
            author: signer.public_key(),
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

    pub fn parents(&self) -> &[BlockId] {
        &self.parents
    }

    /// Validates the internal consistency of the block.
    ///
    /// This performs two critical security checks:
    /// 1. Content Integrity: Re-hashes the data to ensure it matches the `id`.
    /// 2. Authenticity: Verifies the `signature` against the `author`'s public key.
    pub fn verify_integrity(&self) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "block_verify_integrity", block_id = ?self.id);
        let _enter = span.enter();

        let calculated_id =
            Self::compute_id(&self.content, &self.rank, &self.block_type, &self.parents);
        if self.id != calculated_id {
            tracing::error!(stored = ?self.id, calculated = ?calculated_id, "Block ID mismatch");
            return Err(SovereignError::BlockIdMismatch(self.id));
        }

        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| {
                tracing::error!(error = %e, "Block signature verification failed");
                SovereignError::SignatureFailure(e.to_string())
            })?;

        Ok(())
    }

    /// Computes the canonical SHA-256 hash of the block's data.
    /// Domain separation is used to prevent hash collisions with other object types.
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
