use akshara_aadhaara::{BlockId, Signature, SigningPublicKey};
use fractional_index::FractionalIndex;
use serde::{Deserialize, Serialize};

/// A paragraph or sentence node inside a CollaborativeText document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParagraphNode {
    /// The fractional index key determining the node's order.
    pub key: FractionalIndex,
    /// The text content of the paragraph.
    pub text: String,
    /// The Block ID (CID) of the block storing this paragraph.
    pub block_id: BlockId,
    /// The public key of the author who wrote this paragraph.
    pub author: SigningPublicKey,
    /// The signature of the author.
    pub signature: Signature,
}

/// A collaborative text document structure preserving sentence/paragraph-level lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborativeText {
    /// The ordered list of text paragraph/sentence nodes.
    pub paragraphs: Vec<ParagraphNode>,
}

impl CollaborativeText {
    /// Create a new CollaborativeText wrapper.
    pub fn new(paragraphs: Vec<ParagraphNode>) -> Self {
        Self { paragraphs }
    }
}
