pub(crate) mod base;
pub(crate) mod graph;
pub(crate) mod identity;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod traversal;

// --- Public API ---

pub use base::address::{
    Address, BlockId, CODEC_AKSHARA_BLOCK, CODEC_AKSHARA_MANIFEST, GraphId, ManifestId,
};
pub use base::crypto::{
    BlockContent, EncryptionPublicKey, GraphKey, Lockbox, Signature, SigningPublicKey,
    SovereignSigner,
};
pub use base::encoding::{from_canonical_bytes, to_canonical_bytes};
pub use base::error::{IntegrityError, SovereignError};

pub use graph::{Block, Manifest, ManifestHeader};
pub use identity::SecretIdentity;
pub use protocol::{Comparison, Delta, Heads, Portion, Reconciler};
pub use state::{GraphStore, InMemoryStore};
pub use traversal::{Auditor, BlockWalker, GraphWalker, IndexBuilder};
