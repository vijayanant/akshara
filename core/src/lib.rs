pub(crate) mod base;
pub(crate) mod graph;
pub(crate) mod identity;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod traversal;

// --- Public API ---

pub use base::address::{
    Address, BlockId, CODEC_SOVEREIGN_BLOCK, CODEC_SOVEREIGN_MANIFEST, GraphId, ManifestId,
};
pub use base::crypto::{
    EncryptionPublicKey, GraphKey, Lockbox, Signature, SigningPublicKey, SovereignSigner,
};
pub use base::error::{IntegrityError, SovereignError};

pub use graph::{Block, Manifest, ManifestHeader};
pub use identity::SecretIdentity;
pub use protocol::{Delta, Heads, Portion, Reconciler};
pub use state::{GraphStore, InMemoryStore};
pub use traversal::{BlockWalker, GraphWalker};
