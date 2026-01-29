use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

pub mod block;
pub mod manifest;
pub mod walker;

pub use block::Block;
pub use manifest::Manifest;
pub use walker::{BlockWalker, GraphWalker};

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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct DocId(pub Uuid);

impl DocId {
    pub fn new() -> Self {
        DocId(Uuid::new_v4())
    }
}

impl Default for DocId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for DocId {
    fn from(uuid: Uuid) -> Self {
        DocId(uuid)
    }
}

impl AsRef<Uuid> for DocId {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl FromStr for DocId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s)?;
        Ok(DocId(uuid))
    }
}
