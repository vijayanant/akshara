// --- Content Identifiers (CIDs) ---

use core::fmt;
use std::str::FromStr;
use uuid::Uuid;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};

use crate::base::error::{AksharaError, IntegrityError};

/// The global Multicodec for an opaque Data Block (Encrypted-then-Signed).
///
/// Ref: https://github.com/multiformats/multicodec/blob/master/table.csv
/// We use 0x57 (Akshara Block) to distinguish protocol content from generic bytes.
pub const CODEC_AKSHARA_BLOCK: u64 = 0x57;

/// The global Multicodec for a signed Graph Snapshot (Manifest).
///
/// Ref: https://github.com/multiformats/multicodec/blob/master/table.csv
/// We use 0x58 (Akshara Manifest) to mark public metadata entry points.
pub const CODEC_AKSHARA_MANIFEST: u64 = 0x58;

/// `Address` is the opaque, universal pointer of the Sovereign Web.
///
/// It wraps a `Cid` (Content Identifier) to provide location-independent,
/// cryptographically verifiable addressing for any piece of data.
///
/// By using `Address` instead of raw library types, we ensure that the
/// core logic remains "Blind" to the underlying hashing and transport physics,
/// adhering to the Principle of Maximum Information Hiding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
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

impl From<Cid> for Address {
    fn from(cid: Cid) -> Self {
        Self(cid)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = AksharaError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let cid = Cid::read_bytes(&mut cursor)
            .map_err(|_| AksharaError::Integrity(IntegrityError::MalformedId))?;

        // THE FORTRESS RULE: Entire buffer must be consumed
        if cursor.position() != bytes.len() as u64 {
            return Err(AksharaError::Integrity(IntegrityError::MalformedId));
        }

        // AKSHARA MANDATE: Only CIDv1 is permitted for algorithm agility
        if cid.version() != cid::Version::V1 {
            return Err(AksharaError::Integrity(IntegrityError::MalformedId));
        }

        Ok(Self(cid))
    }
}

impl FromStr for Address {
    type Err = AksharaError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid =
            Cid::from_str(s).map_err(|_| AksharaError::Integrity(IntegrityError::MalformedId))?;
        Ok(Self(cid))
    }
}

/// `BlockId` is a semantic refinement of an `Address` representing a Data Block.
///
/// It is guaranteed to possess a Multicodec of `CODEC_AKSHARA_BLOCK` (CODEC_AKSHARA_BLOCK).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockId(Address);

impl BlockId {
    /// Creates a new BlockId from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_AKSHARA_BLOCK, hash);
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
    type Error = AksharaError;
    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        if addr.codec() != CODEC_AKSHARA_BLOCK {
            return Err(AksharaError::Integrity(IntegrityError::TypeMismatch(
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
    type Err = AksharaError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = Address::from_str(s)?;
        BlockId::try_from(addr)
    }
}

impl TryFrom<&[u8]> for BlockId {
    type Error = AksharaError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let addr = Address::try_from(bytes)?;
        BlockId::try_from(addr)
    }
}

/// `ManifestId` is a semantic refinement of an `Address` representing a Manifest.
///
/// It is guaranteed to possess a Multicodec of `CODEC_AKSHARA_MANIFEST` (CODEC_AKSHARA_MANIFEST).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ManifestId(Address);

impl ManifestId {
    /// Creates a new ManifestId from a SHA2-256 digest.
    pub fn from_sha256(digest: &[u8]) -> Self {
        let hash = Code::Sha2_256.digest(digest);
        let cid = Cid::new_v1(CODEC_AKSHARA_MANIFEST, hash);
        ManifestId(Address(cid))
    }

    /// Returns the "Null Identifier" representing the genesis of a timeline.
    ///
    /// Uses a SHA2-256 digest of 32 zeros.
    pub fn null() -> Self {
        let hash = Code::Sha2_256.digest(&[0u8; 32]);
        let cid = Cid::new_v1(CODEC_AKSHARA_MANIFEST, hash);
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
    type Error = AksharaError;
    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        if addr.codec() != CODEC_AKSHARA_MANIFEST {
            return Err(AksharaError::Integrity(IntegrityError::TypeMismatch(
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
    type Err = AksharaError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = Address::from_str(s)?;
        ManifestId::try_from(addr)
    }
}

impl TryFrom<&[u8]> for ManifestId {
    type Error = AksharaError;
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

    /// Creates a GraphId from raw 16-byte UUID bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
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
