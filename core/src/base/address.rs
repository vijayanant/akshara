// --- Content Identifiers (CIDs) ---

use core::fmt;
use std::str::FromStr;
use uuid::Uuid;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base::error::{IntegrityError, SovereignError};

/// Multicodec for Sovereign Blocks (L0 Node)
pub const CODEC_SOVEREIGN_BLOCK: u64 = 0x50;
/// Multicodec for Sovereign Manifests (Snapshots)
pub const CODEC_SOVEREIGN_MANIFEST: u64 = 0x51;

/// `BlockId` is a cryptographically bound identifier for a Sovereign data block.
///
/// We wrap `cid::Cid` to prevent "Library Physics" from leaking into the domain logic.
/// This allows us to change the underlying identifier technology without breaking
/// the platform's API.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockId(Cid);

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

    /// Internal constructor for crate-only logic or testing.
    #[allow(dead_code)]
    pub(crate) fn from_cid(cid: Cid) -> Self {
        BlockId(cid)
    }

    /// Internal accessor for the underlying CID.
    #[allow(dead_code)]
    pub(crate) fn as_cid(&self) -> &Cid {
        &self.0
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

    /// Returns the raw binary representation of the identifier.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
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

    /// Implements the "Strict Ingestion" rule.
    ///
    /// We use a `Cursor` to ensure the entire byte slice is consumed.
    /// If there are trailing bytes, we reject the ID. This prevents attackers from
    /// appending malicious metadata or "hidden tags" to a valid identifier.
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

/// `ManifestId` identifies a signed snapshot of a graph.
///
/// Uses Multicodec `0x51` to prevent type-confusion attacks where a Manifest
/// might be mistaken for a Data Block.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ManifestId(Cid);

impl ManifestId {
    /// Creates a CID v1 for a Sovereign Manifest from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        Self::from_digest(Code::Sha2_256, digest)
    }

    pub fn from_digest(code: Code, digest: &[u8]) -> Self {
        let hash = code.digest(digest);
        let cid = Cid::new_v1(CODEC_SOVEREIGN_MANIFEST, hash);
        ManifestId(cid)
    }

    #[allow(dead_code)]
    pub(crate) fn from_cid(cid: Cid) -> Self {
        ManifestId(cid)
    }

    #[allow(dead_code)]
    pub(crate) fn as_cid(&self) -> &Cid {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
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

/// `GraphId` is the stable, permanent identity of a Sovereign document or project.
///
/// While data content changes (CID updates), the `GraphId` remains constant.
/// It acts as the "Home Address" for all historical manifestations of a graph.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GraphId(Uuid);

impl GraphId {
    pub fn new() -> Self {
        GraphId(Uuid::new_v4())
    }

    #[allow(dead_code)]
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        GraphId(Uuid::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
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

impl FromStr for GraphId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s)?;
        Ok(GraphId(uuid))
    }
}

impl fmt::Display for GraphId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
