// --- Content Identifiers (CIDs) ---

use core::fmt;
use std::str::FromStr;
use uuid::Uuid;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base::{IntegrityError, SovereignError};

/// Multicodec for Sovereign Blocks (L0 Node)
/// Identifies an encrypted, signed block.
pub const CODEC_SOVEREIGN_BLOCK: u64 = 0x50;
/// Multicodec for Sovereign Manifests (Snapshots)
/// Identifies a signed graph state entry.
pub const CODEC_SOVEREIGN_MANIFEST: u64 = 0x51;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockId(pub Cid);

impl BlockId {
    /// Creates a CID v1 for a Sovereign Block from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        Self::from_digest(Code::Sha2_256, digest)
    }

    /// Creates a CID v1 for a Sovereign Block using a specific algorithm.
    pub fn from_digest(code: Code, digest: &[u8]) -> Self {
        let hash = code.digest(digest);
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
        // Use default CID string representation (Base32 for CIDv1)
        write!(f, "{}", self.0)
    }
}

impl FromStr for BlockId {
    type Err = SovereignError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid =
            Cid::from_str(s).map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;
        if cid.codec() != CODEC_SOVEREIGN_BLOCK {
            return Err(SovereignError::Integrity(IntegrityError::MalformedId));
        }
        Ok(BlockId(cid))
    }
}

impl TryFrom<&[u8]> for BlockId {
    type Error = SovereignError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let cid = Cid::read_bytes(&mut cursor)
            .map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;

        if cursor.position() != bytes.len() as u64 || cid.codec() != CODEC_SOVEREIGN_BLOCK {
            return Err(SovereignError::Integrity(IntegrityError::MalformedId));
        }
        Ok(BlockId(cid))
    }
}

// Custom Serde for BlockId to use string representation
impl Serialize for BlockId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for BlockId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BlockId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ManifestId(pub Cid);

impl ManifestId {
    /// Creates a CID v1 for a Sovereign Manifest from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        Self::from_digest(Code::Sha2_256, digest)
    }

    /// Creates a CID v1 for a Sovereign Manifest using a specific algorithm.
    pub fn from_digest(code: Code, digest: &[u8]) -> Self {
        let hash = code.digest(digest);
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
    type Err = SovereignError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid =
            Cid::from_str(s).map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;
        if cid.codec() != CODEC_SOVEREIGN_MANIFEST {
            return Err(SovereignError::Integrity(IntegrityError::MalformedId));
        }
        Ok(ManifestId(cid))
    }
}

impl TryFrom<&[u8]> for ManifestId {
    type Error = SovereignError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let cid = Cid::read_bytes(&mut cursor)
            .map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;

        if cursor.position() != bytes.len() as u64 || cid.codec() != CODEC_SOVEREIGN_MANIFEST {
            return Err(SovereignError::Integrity(IntegrityError::MalformedId));
        }
        Ok(ManifestId(cid))
    }
}

// Custom Serde for ManifestId
impl Serialize for ManifestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for ManifestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ManifestId::from_str(&s).map_err(serde::de::Error::custom)
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
