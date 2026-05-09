pub(crate) mod base;
pub(crate) mod graph;
pub(crate) mod identity;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod traversal;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// --- Public API ---

pub use base::address::{
    Address, BlockId, CODEC_AKSHARA_BLOCK, CODEC_AKSHARA_MANIFEST, GraphId, Lakshana, ManifestId,
};
pub use base::crypto::{
    AksharaSigner, BlockContent, EncryptionPublicKey, GraphKey, Lockbox, Signature,
    SigningPublicKey,
};
pub use base::encoding::{from_canonical_bytes, to_canonical_bytes};
pub use base::error::{AksharaError, IntegrityError};

pub use graph::{Block, BlockType, Manifest};
pub use identity::{
    GraphDescriptor, IdentityGraph, MasterIdentity, SecretIdentity, graph::IDENTITY_GRAPH_KEY,
    paths,
};
pub use protocol::{Comparison, Delta, Heads, Portion, Reconciler};
pub use state::{GraphStore, InMemoryStore};
pub use traversal::{Auditor, BlockWalker, GraphWalker, IndexBuilder};
