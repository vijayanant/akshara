pub(crate) mod base;
pub(crate) mod graph;
pub(crate) mod identity;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod traversal;

// --- Public API ---

pub use base::address::{
    Address, BlockId, CODEC_AKSHARA_BLOCK, CODEC_AKSHARA_MANIFEST, GraphId, Lakshana, ManifestId,
};
pub use base::crypto::{
    AksharaSigner, EncryptionPublicKey, GraphKey, Lockbox, Signature, SigningPublicKey,
};
pub use base::encoding::{from_canonical_bytes, to_canonical_bytes};
pub use base::error::{AksharaError, IntegrityError};

pub use graph::{Block, BlockType, Manifest};
pub use identity::{MasterIdentity, SecretIdentity};
pub use protocol::{Comparison, Delta, Heads, Portion, Reconciler};
pub use state::{GraphStore, InMemoryStore};
pub use traversal::{Auditor, BlockWalker, GraphWalker, IndexBuilder};
