use crate::base::address::{BlockId, GraphId};
use crate::base::crypto::{AksharaSigner, BlockContent, GraphKey, Signature, SigningPublicKey};
use crate::base::error::{AksharaError, CryptoError, IntegrityError};
use cid::Cid;
use hmac::{Hmac, Mac};
use metrics::counter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use tracing::{Level, info, span};

/// Represents the semantic purpose of a Block.
///
/// Follows the Reserved Codec Registry (AIP-001). Types starting with
/// 'akshara.' are reserved for the foundation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockType {
    #[serde(rename = "akshara.index.v1")]
    AksharaIndexV1,
    #[serde(rename = "akshara.data.v1")]
    AksharaDataV1,
    #[serde(rename = "akshara.auth.v1")]
    AksharaAuthV1,
    #[serde(rename = "akshara.revocation.v1")]
    AksharaRevocationV1,
    #[serde(rename = "akshara.trust.v1")]
    AksharaTrustV1,
    #[serde(rename = "akshara.succession.v1")]
    AksharaSuccessionV1,
    /// Application-defined custom type. Must NOT start with 'akshara.'.
    Custom(String),
}

impl BlockType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AksharaIndexV1 => "akshara.index.v1",
            Self::AksharaDataV1 => "akshara.data.v1",
            Self::AksharaAuthV1 => "akshara.auth.v1",
            Self::AksharaRevocationV1 => "akshara.revocation.v1",
            Self::AksharaTrustV1 => "akshara.trust.v1",
            Self::AksharaSuccessionV1 => "akshara.succession.v1",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl From<&str> for BlockType {
    fn from(s: &str) -> Self {
        match s {
            "akshara.index.v1" => Self::AksharaIndexV1,
            "akshara.data.v1" => Self::AksharaDataV1,
            "akshara.auth.v1" => Self::AksharaAuthV1,
            "akshara.revocation.v1" => Self::AksharaRevocationV1,
            "akshara.trust.v1" => Self::AksharaTrustV1,
            "akshara.succession.v1" => Self::AksharaSuccessionV1,
            // Legacy/Short-name mapping for backward compatibility in tests
            "index" => Self::AksharaIndexV1,
            "data" => Self::AksharaDataV1,
            "auth" => Self::AksharaAuthV1,
            "revocation" => Self::AksharaRevocationV1,
            _ => Self::Custom(s.to_string()),
        }
    }
}

impl From<String> for BlockType {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl PartialEq<&str> for BlockType {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<str> for BlockType {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A `Block` is the atomic unit of content in Akshara.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub(crate) id: BlockId,
    pub(crate) author: SigningPublicKey,
    pub(crate) signature: Signature,
    pub(crate) content: BlockContent,
    pub(crate) block_type: BlockType,
    pub(crate) parents: Vec<BlockId>,
}

impl Block {
    pub fn new(
        graph_id: GraphId,
        plaintext: Vec<u8>,
        block_type: BlockType,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl AksharaSigner,
    ) -> Result<Self, AksharaError> {
        // DEDUPLICATION RITUAL:
        // We use a deterministic nonce derived from (Key + Plaintext).
        // This ensures that identical content in the same graph results in the same CID,
        // enabling massive storage and sync savings (Pillar 2: Permanence).
        let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .map_err(|e| AksharaError::InternalError(format!("HMAC init failed: {}", e)))?;
        hmac.update(&plaintext);
        let hmac_result = hmac.finalize().into_bytes();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hmac_result[..24]);

        let ad = Self::compute_ad(&graph_id, &signer.public_key(), &block_type, &parents);
        let content = BlockContent::encrypt(&plaintext, key, nonce, &ad)?;

        Ok(Self::create(content, block_type, parents, signer))
    }

    pub fn new_index(
        graph_id: GraphId,
        index: BTreeMap<String, Cid>,
        parents: Vec<BlockId>,
        key: &GraphKey,
        signer: &impl AksharaSigner,
    ) -> Result<Self, AksharaError> {
        let plaintext = crate::base::encoding::to_canonical_bytes(&index)?;

        // Deterministic Nonce for Index deduplication
        let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .map_err(|e| AksharaError::InternalError(format!("HMAC init failed: {}", e)))?;
        hmac.update(&plaintext);
        let hmac_result = hmac.finalize().into_bytes();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hmac_result[..24]);

        let ad = Self::compute_ad(
            &graph_id,
            &signer.public_key(),
            &BlockType::AksharaIndexV1,
            &parents,
        );

        let content = BlockContent::encrypt(&plaintext, key, nonce, &ad)?;

        Ok(Self::create(
            content,
            BlockType::AksharaIndexV1,
            parents,
            signer,
        ))
    }

    fn create(
        content: BlockContent,
        block_type: BlockType,
        parents: Vec<BlockId>,
        signer: &impl AksharaSigner,
    ) -> Self {
        let id = Self::compute_id(&content, &block_type, &parents);
        let signature = signer.sign(id.as_ref());

        info!(block_id = ?id, block_type = %block_type, "Block created");
        counter!("akshara.block.created").increment(1);

        Block {
            id,
            author: signer.public_key(),
            signature,
            content,
            block_type,
            parents,
        }
    }

    pub fn decrypt(&self, graph_id: &GraphId, key: &GraphKey) -> Result<Vec<u8>, AksharaError> {
        let ad = Self::compute_ad(graph_id, &self.author, &self.block_type, &self.parents);
        self.content.decrypt(key, &ad)
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

    pub fn block_type(&self) -> &BlockType {
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
        block_type: BlockType,
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

    pub fn verify_integrity(&self) -> Result<(), AksharaError> {
        let span = span!(Level::DEBUG, "block_verify_integrity", block_id = ?self.id);
        let _enter = span.enter();

        let calculated_id = Self::compute_id(&self.content, &self.block_type, &self.parents);
        if self.id != calculated_id {
            return Err(AksharaError::Integrity(IntegrityError::BlockIdMismatch(
                self.id,
            )));
        }

        self.author
            .verify(self.id.as_ref(), &self.signature)
            .map_err(|e| AksharaError::Crypto(CryptoError::InvalidSignature(e.to_string())))?;

        Ok(())
    }

    /// Computes the canonical Associated Data (AD) for a block.
    ///
    /// This binds the ciphertext to the Graph, the Author, the Type, and the History.
    fn compute_ad(
        graph_id: &GraphId,
        author: &SigningPublicKey,
        block_type: &BlockType,
        parents: &[BlockId],
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"AKSHARA_V1_AD");
        hasher.update(graph_id.as_bytes());
        hasher.update(author.as_bytes());
        hasher.update(block_type.as_str().as_bytes());
        for p in parents {
            hasher.update(p.as_ref());
        }
        hasher.finalize().to_vec()
    }

    fn compute_id(content: &BlockContent, block_type: &BlockType, parents: &[BlockId]) -> BlockId {
        let mut hasher = Sha256::new();
        hasher.update(b"AKSHARA_V1_BLOCK");
        hasher.update(content.as_bytes());
        hasher.update(content.nonce());
        hasher.update(block_type.as_str().as_bytes());

        for parent in parents {
            hasher.update(parent.as_ref());
        }

        BlockId::from_sha256(&hasher.finalize())
    }
}
