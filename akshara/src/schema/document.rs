use akshara_aadhaara::{
    Address, AksharaError, BlockId, GraphId, GraphKey, GraphStore, SecretIdentity,
};
use async_trait::async_trait;
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
    /// Sentence-level collaborative text block splitting.
    CollaborativeText,
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
#[async_trait]
pub trait AksharaDocument: Serialize + for<'de> Deserialize<'de> + Send + Sync {
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

    /// Serializes all fields that require block layouts and returns their relative paths and Addresses.
    async fn serialize_fields<S: GraphStore + ?Sized>(
        &self,
        _graph_id: &GraphId,
        _key: &GraphKey,
        _signer: &SecretIdentity,
        _store: &S,
        _doc_path: &str,
    ) -> Result<Vec<(String, Address)>, AksharaError> {
        Ok(vec![])
    }

    /// Deserializes all fields that require block layouts and updates self.
    async fn deserialize_fields<S: GraphStore + ?Sized>(
        &mut self,
        _graph_id: &GraphId,
        _key: &GraphKey,
        _store: &S,
        _doc_path: &str,
        _content_root: &BlockId,
    ) -> Result<(), AksharaError> {
        Ok(())
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
