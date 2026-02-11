pub mod base;

pub mod graph;
pub mod identity;
pub mod protocol;
pub mod state;
pub mod traversal;

// Re-export foundational types for internal compatibility
pub use base::address::{
    BlockId, CODEC_SOVEREIGN_BLOCK, CODEC_SOVEREIGN_MANIFEST, GraphId, ManifestId,
};
pub use base::crypto::{
    BlockContent, EncryptionPublicKey, EncryptionSecretKey, GraphKey, Lockbox, Signature,
    SigningPublicKey, SigningSecretKey, SovereignSigner,
};
pub use base::error::{CryptoError, IdentityError, IntegrityError, SovereignError, StoreError};
