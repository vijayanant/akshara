//! Foundational traits and types for structured document patterns.

use akshara_aadhaara::{Address, AksharaError};
use serde::{Deserialize, Serialize};

/// How a field in an Akshara document maps to physical storage units (Blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockMode {
    /// The field is stored as a single standalone block. Default for most fields.
    Block,
    /// Each item in the collection (Vec) is stored as its own independent block.
    /// Uses fractional indexing to maintain order.
    Collection,
    /// The data is split into multiple chunks (sub-blocks) organized in a Merkle tree.
    /// Recommended for large binary payloads (> 1MB).
    Chunked,
}

/// Metadata describing a specific field within an Akshara document pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDescriptor {
    /// The coordinate path relative to the document root (e.g., "meta/title").
    pub path: String,
    /// The storage mapping mode for this field.
    pub mode: BlockMode,
    /// Whether this field should be lazily loaded (deferred fetch).
    pub is_lazy: bool,
}

/// Defines the "Geography" of a structured document pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSchema {
    /// The unique name of the document type (e.g., "PatientRecord").
    pub type_name: String,
    /// The version of this schema.
    pub version: u32,
    /// The list of fields and their physical mapping rules.
    pub fields: Vec<FieldDescriptor>,
}

/// `AksharaDocument` is the foundational trait for all structured data.
///
/// It allows the SDK to automatically transform Rust structs into
/// patterns of Merkle blocks while preserving bit-verifiable integrity.
pub trait AksharaDocument: Serialize + for<'de> Deserialize<'de> {
    /// Returns the schema describing how this type maps to blocks.
    fn schema() -> DocumentSchema;

    /// Serializes the document to canonical DAG-CBOR bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, AksharaError> {
        akshara_aadhaara::to_canonical_bytes(self)
    }

    /// Deserializes a document from canonical DAG-CBOR bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, AksharaError> {
        akshara_aadhaara::from_canonical_bytes(bytes)
    }

    /// Returns all paths within the document that are marked as lazy.
    fn lazy_paths() -> Vec<String> {
        Self::schema()
            .fields
            .iter()
            .filter(|f| f.is_lazy)
            .map(|f| f.path.clone())
            .collect()
    }
}

/// `LazyField` acts as a placeholder for document fields that are stored
/// in the graph but not yet fetched into memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazyField<T> {
    /// The coordinate path where the data is located.
    path: String,
    /// The address of the block if it's already known, otherwise None.
    address: Option<Address>,
    #[serde(skip)]
    _marker: std::marker::PhantomData<T>,
}

impl<T> LazyField<T> {
    /// Creates a new lazy placeholder for the given path.
    pub fn new(path: String) -> Self {
        Self {
            path,
            address: None,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the coordinate path of the data.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the address of the data, if resolved.
    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }
}
