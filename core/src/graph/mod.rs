use serde::{Deserialize, Serialize};

pub mod block;
pub mod manifest;
pub mod walker;

pub use block::Block;
pub use manifest::Manifest;
pub use walker::GraphWalker;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockId(pub [u8; 32]);

impl AsRef<[u8]> for BlockId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for BlockId {
    fn from(bytes: [u8; 32]) -> Self {
        BlockId(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ManifestId(pub [u8; 32]);

impl AsRef<[u8]> for ManifestId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ManifestId {
    fn from(bytes: [u8; 32]) -> Self {
        ManifestId(bytes)
    }
}
