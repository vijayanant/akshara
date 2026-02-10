use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

pub mod block;
pub mod manifest;
pub mod walker;

pub use block::Block;
pub use manifest::Manifest;
pub use walker::{BlockWalker, GraphWalker};

// --- Content Identifiers (CIDs) ---

/// Multicodec for Sovereign Blocks (L0 Node)
pub const CODEC_SOVEREIGN_BLOCK: u64 = 0x50;
/// Multicodec for Sovereign Manifests (Snapshots)
pub const CODEC_SOVEREIGN_MANIFEST: u64 = 0x51;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockId(pub Cid);

impl BlockId {
    /// Creates a CID v1 for a Sovereign Block from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_SOVEREIGN_BLOCK, hash);
        BlockId(cid)
    }

    pub fn version(&self) -> u64 {
        self.0.version().into()
    }

    pub fn codec(&self) -> u64 {
        self.0.codec()
    }

    pub fn hash_type(&self) -> u64 {
        self.0.hash().code()
    }
}

impl AsRef<[u8]> for BlockId {
    fn as_ref(&self) -> &[u8] {
        self.0.hash().digest()
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for BlockId {
    type Err = cid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(BlockId(Cid::from_str(s)?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ManifestId(pub Cid);

impl ManifestId {
    /// Creates a CID v1 for a Sovereign Manifest from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_SOVEREIGN_MANIFEST, hash);
        ManifestId(cid)
    }
}

impl AsRef<[u8]> for ManifestId {
    fn as_ref(&self) -> &[u8] {
        self.0.hash().digest()
    }
}

impl fmt::Display for ManifestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ManifestId {
    type Err = cid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ManifestId(Cid::from_str(s)?))
    }
}

// --- Graph Namespace ---

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GraphId(pub Uuid);

impl GraphId {
    pub fn new() -> Self {
        GraphId(Uuid::new_v4())
    }
}

impl Default for GraphId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for GraphId {
    fn from(uuid: Uuid) -> Self {
        GraphId(uuid)
    }
}

impl AsRef<Uuid> for GraphId {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl FromStr for GraphId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s)?;
        Ok(GraphId(uuid))
    }
}
