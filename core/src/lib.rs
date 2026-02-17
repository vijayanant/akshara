pub(crate) mod base;
pub(crate) mod graph;
pub(crate) mod identity;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod traversal;

// --- Public API ---

pub use base::address::{BlockId, GraphId, ManifestId};
pub use base::crypto::{
    EncryptionPublicKey, GraphKey, Lockbox, Signature, SigningPublicKey, SovereignSigner,
};
pub use base::error::{IntegrityError, SovereignError};

pub use graph::{Block, Manifest};
pub use identity::SecretIdentity;
pub use protocol::{SyncEngine, SyncRequest, SyncResponse};
pub use state::{GraphStore, InMemoryStore};
pub use traversal::{BlockWalker, GraphWalker};
