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

/// `Address` is the unified, opaque identifier for any piece of data in the Sovereign Web.
///
/// It wraps the underlying library types to ensure that "Library Physics" do not
/// leak into the platform's public API.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address(Cid);

impl Address {
    /// Returns the raw binary representation of the address.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Returns the internal multicodec of the address.
    pub fn codec(&self) -> u64 {
        self.0.codec()
    }

    /// Internal accessor for the underlying CID.
    pub(crate) fn as_cid(&self) -> &Cid {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = SovereignError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let cid = Cid::read_bytes(&mut cursor)
            .map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;

        if cursor.position() != bytes.len() as u64 {
            return Err(SovereignError::Integrity(IntegrityError::MalformedId));
        }
        Ok(Self(cid))
    }
}

impl FromStr for Address {
    type Err = SovereignError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid =
            Cid::from_str(s).map_err(|_| SovereignError::Integrity(IntegrityError::MalformedId))?;
        Ok(Self(cid))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// `BlockId` is a cryptographically bound identifier for a Sovereign data block.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockId(Address);

impl BlockId {
    /// Creates a new BlockId from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_SOVEREIGN_BLOCK, hash);
        BlockId(Address(cid))
    }

    /// Returns the raw binary representation of the identifier.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn codec(&self) -> u64 {
        self.0.codec()
    }

    pub(crate) fn as_cid(&self) -> &Cid {
        self.0.as_cid()
    }
}

impl From<BlockId> for Address {
    fn from(id: BlockId) -> Self {
        id.0
    }
}

impl TryFrom<Address> for BlockId {
    type Error = SovereignError;
    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        if addr.codec() != CODEC_SOVEREIGN_BLOCK {
            return Err(SovereignError::Integrity(IntegrityError::TypeMismatch(
                addr, "BlockId",
            )));
        }
        Ok(BlockId(addr))
    }
}

impl AsRef<[u8]> for BlockId {
    fn as_ref(&self) -> &[u8] {
        self.as_cid().hash().digest()
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
        let addr = Address::from_str(s)?;
        BlockId::try_from(addr)
    }
}

impl TryFrom<&[u8]> for BlockId {
    type Error = SovereignError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let addr = Address::try_from(bytes)?;
        BlockId::try_from(addr)
    }
}

/// `ManifestId` identifies a signed snapshot of a graph.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ManifestId(Address);

impl ManifestId {
    /// Creates a new ManifestId from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_SOVEREIGN_MANIFEST, hash);
        ManifestId(Address(cid))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn codec(&self) -> u64 {
        self.0.codec()
    }

    pub(crate) fn as_cid(&self) -> &Cid {
        self.0.as_cid()
    }
}

impl From<ManifestId> for Address {
    fn from(id: ManifestId) -> Self {
        id.0
    }
}

impl TryFrom<Address> for ManifestId {
    type Error = SovereignError;
    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        if addr.codec() != CODEC_SOVEREIGN_MANIFEST {
            return Err(SovereignError::Integrity(IntegrityError::TypeMismatch(
                addr,
                "ManifestId",
            )));
        }
        Ok(ManifestId(addr))
    }
}

impl AsRef<[u8]> for ManifestId {
    fn as_ref(&self) -> &[u8] {
        self.as_cid().hash().digest()
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
        let addr = Address::from_str(s)?;
        ManifestId::try_from(addr)
    }
}

impl TryFrom<&[u8]> for ManifestId {
    type Error = SovereignError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let addr = Address::try_from(bytes)?;
        ManifestId::try_from(addr)
    }
}

// --- Graph Namespace ---

/// `GraphId` is the stable, permanent identity of a Sovereign document or project.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GraphId(Uuid);

impl GraphId {
    pub fn new() -> Self {
        GraphId(Uuid::new_v4())
    }

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
