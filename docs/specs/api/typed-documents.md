# Spec 2: Typed Documents

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles §3](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Errors](./errors.md)

---

## Scope

This spec defines:
- The `AksharaDocument` derive macro and its annotations
- The block-mapping modes: `#[block]`, `#[collection]`, `#[chunked]`, `#[collaborative_text]`
- `LazyField<T>` — deferred loading handles
- Schema metadata storage in the index
- How typed documents map to blocks, paths, and CID structures

It does **not** cover: the `Graph` API surface (see [Client & Graph](./client-and-graph.md)), error variants (see [Errors](./errors.md)).

---

## 1. The `AksharaDocument` Derive Macro

### 1.1 Usage

```rust
#[derive(AksharaDocument, Serialize, Deserialize, Clone)]
struct PatientRecord {
    // ... fields with annotations
}
```

The derive macro automatically generates:
- Implementation of the `AksharaDocument` trait (defined below)
- Serialization/deserialization helper calls via DAG-CBOR
- Path-to-field mapping derived from the field names
- Dynamic field serialization and deserialization using the layout adapters
- Schema metadata registration

### 1.2 The `AksharaDocument` Trait

```rust
#[async_trait]
pub trait AksharaDocument: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Returns the schema describing how this type maps to blocks.
    fn schema() -> DocumentSchema;

    /// Serializes the document to canonical DAG-CBOR bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, AksharaError>;

    /// Deserializes a document from canonical DAG-CBOR bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, AksharaError>;

    /// Serializes all fields that require block adapters and returns their relative paths and Addresses.
    async fn serialize_fields<S: GraphStore + ?Sized>(
        &self,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        doc_path: &str,
    ) -> Result<Vec<(String, Address)>, AksharaError>;

    /// Deserializes all fields that require block adapters and updates self.
    async fn deserialize_fields<S: GraphStore + ?Sized>(
        &mut self,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
        doc_path: &str,
        content_root: &akshara_aadhaara::BlockId,
    ) -> Result<(), AksharaError>;

    /// Returns all paths within the document that are marked as lazy.
    fn lazy_paths() -> Vec<String>;
}
```

### 1.3 `DocumentSchema`

```rust
pub struct DocumentSchema {
    /// The type name (e.g., "PatientRecord").
    pub type_name: String,

    /// The schema version.
    pub version: u32,

    /// All field descriptors within this document.
    pub fields: Vec<FieldDescriptor>,
}

pub struct FieldDescriptor {
    /// The path segment for this field within the document.
    pub path: String,

    /// How this field maps to blocks.
    pub mode: BlockMode,

    /// Whether this field is lazily loaded.
    pub is_lazy: bool,
}

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
```

---

## 2. Field Annotations

Field paths are automatically derived from the struct field names relative to the document root (e.g. `doc_path/field_name`). The mapping behavior is configured using standard attributes.

### 2.1 `#[block]` (default)

Creates a standalone block for the field's serialized value. Used for structured data (structs, nested maps, or standard primitive values).

```rust
struct Demographics {
    name: String,
    age: u32,
}

#[derive(AksharaDocument)]
struct Patient {
    #[block]
    demographics: Demographics,
}
```

### 2.2 `#[collection]`

Each item in a `Vec<T>` gets its own independent block, indexed within a sub-index map using fractional indexing.

**When to use:**
- Lists that grow over time
- Items that are independently addressable or editable
- Minimizing merge conflicts on concurrent edits

```rust
#[derive(AksharaDocument)]
struct Patient {
    #[collection]
    consultations: Vec<Consultation>,
}
```

**Fractional indexing:** The items are indexed using ordered strings (e.g. `"a0000"`, `"a0001"`). Midpoint strings are computed during insertions to preserve order without re-Ciding neighboring blocks.

### 2.3 `#[chunked]`

Splits large binary or text fields into fixed-size chunks organized under a Merkle sub-index. Recommended for payloads exceeding 1MB (e.g. PDFs, images, or large raw datasets).

```rust
#[derive(AksharaDocument)]
struct Document {
    #[chunked]
    content: Vec<u8>,
}
```

The chunk size can be configured dynamically using `ChunkedBlockAdapter::set_chunk_size(size)`.

### 2.4 `#[collaborative_text]`

Splits a large string into sentence-level blocks indexed via fractional indexing. Designed for collaborative text documents where users might concurrently edit different parts of the text.

```rust
#[derive(AksharaDocument)]
struct Note {
    #[collaborative_text]
    body: String,
}
```

### 2.5 `#[lazy]` or `LazyField<T>`

Marks a field as deferred-load. The field is not fetched automatically when reading the parent document. Instead, its `Address` is resolved in the index and stored in a `LazyField<T>` placeholder.

---

## 3. `LazyField<T>`

### 3.1 Definition

```rust
pub struct LazyField<T> {
    path: String,
    address: Option<Address>,
    _marker: std::marker::PhantomData<T>,
}
```

### 3.2 Methods

```rust
impl<T> LazyField<T> {
    /// Creates a new lazy placeholder for the given path.
    pub fn new(path: String) -> Self;

    /// The coordinate path of the lazy data.
    pub fn path(&self) -> &str;

    /// Returns the resolved block address of this lazy field, if known.
    pub fn address(&self) -> Option<&Address>;

    /// Sets the resolved block address.
    pub fn set_address(&mut self, address: Address);
}
```

### 3.3 Behavior

When `Graph::get_document::<PatientRecord>("/patients/001")` is called:
1. The SDK fetches the root document struct from `/patients/001/.akshara.document`.
2. Any field of type `LazyField<T>` will have its path resolved in the Merkle index (e.g. `/patients/001/imaging`).
3. If the path exists in the index, the resolved `Address` is populated into the `LazyField` using `set_address()`.
4. The field remains deferred; to retrieve its content, the developer reads from the stored `address` or path explicitly using the appropriate adapters or graph operations.

---

## 4. How Typed Documents Map to Blocks

### 4.1 Example

```rust
#[derive(AksharaDocument)]
struct Meeting {
    objective: String,  // Defaults to #[block]

    #[collection]
    agenda: Vec<AgendaItem>,

    #[lazy]
    #[chunked]
    spec_pdf: Vec<u8>,
}
```

When `graph.insert("meetings/001", &meeting)` is flushed:

```
meetings/001/
├── (index block)
│   ├── "meta/title" → "Sprint Planning"   (inline — part of this block)
│   └── "meta/objective" → Address(block_abc)
├── meta/
│   └── objective       ← block_abc: "Plan the next release"
├── agenda/
│   ├── "a"             ← block_def: AgendaItem #1
│   └── "c"             ← block_ghi: AgendaItem #2
└── attachments/
    └── spec.pdf/
        ├── (index block)
        │   ├── "chunk/000" → block_jkl
        │   └── "chunk/001" → block_mno
        ├── chunk/000       ← block_jkl: 1 MB of PDF
        └── chunk/001       ← block_mno: 500 KB of PDF
```

**Block count for this meeting:**
- `title` — 0 blocks (inline)
- `objective` — 1 block
- `agenda` (2 items) — 2 blocks
- `spec_pdf` (1.5 MB) — 2 chunk blocks + 1 index = 3 blocks
- Root index — 1 block
- Agenda index — 1 block
- **Total: 8 blocks**

### 4.2 Block Type Assignment

| Mode | Block Type |
|---|---|
| `#[block]` | `BlockType::AksharaDataV1` |
| `#[collection]` | Items: `BlockType::AksharaDataV1`, Sub-Index: `BlockType::AksharaIndexV1` |
| `#[chunked]` | Chunks: `BlockType::AksharaDataV1`, Sub-Index: `BlockType::AksharaIndexV1` |
| `#[collaborative_text]` | Sentences: `BlockType::AksharaDataV1`, Sub-Index: `BlockType::AksharaIndexV1` |

### 4.3 Path Conflict Resolution & Layout

In a Merkle index, a path cannot simultaneously represent both a data leaf block and a directory node (e.g. if we store the main document data directly at `/meetings/001`, we cannot create `/meetings/001/agenda` or other field sub-indices because `/meetings/001` would already be a data leaf).

To avoid this conflict, the SDK reserves the prefix `.akshara.` for metadata and layouts:
- **Main Document Content**: Saved at `doc_path/.akshara.document`
- **Document Layout Schema**: Saved at `doc_path/.akshara.schema`
- **Adapter-Backed Fields**: Saved at `doc_path/field_name` (e.g. `/meetings/001/agenda`)

### 4.4 Parent Lineage

When a field is updated:
- Each field's new block or sub-index has the previous block's CID as its parent.
- Fields that have not changed keep their existing block and CID.
- The parent index block points to the updated blocks, and a new manifest is signed.

---

## 5. Schema Metadata in the Index

### 5.1 Why

The SDK needs to know which paths are `#[lazy]`, `#[collection]`, and `#[chunked]` even for documents it has never loaded. This is required for selective sync (excluding lazy paths) and progressive fetching.

### 5.2 How

Schema metadata is stored as a special block at the document root:

```
meetings/001/
├── .akshara.document  ← main document fields (except adapter ones)
├── .akshara.schema    ← special block, DAG-CBOR encoded DocumentSchema
├── agenda             ← sub-index block for collection
└── spec_pdf           ← sub-index block for chunked chunks
```

The schema block is a regular `AksharaIndexV1` block with a reserved key `.akshara.schema`. It is included in every flush that modifies the document root.

### 5.3 Selective Sync Bootstrap

Because the Relay is **Blind**, it cannot filter by schema. Selective sync is an SDK-level capability.

**The Bootstrap Protocol:**
1. When discovering a new document, the SDK performs an initial **Unfiltered Sync** of the document root index.
2. The SDK decrypts the index and retrieves the `.akshara.schema` block.
3. Once the schema is known locally, the SDK can then perform **Prefix-Filtered Sync** (as defined in [Sync](./sync.md)) to fetch only non-lazy branches from the Relay.

This "Bootstrap Step" ensures the SDK knows the "Geography of the Molecule" before it commits to a large data transfer.

### 5.4 Schema Evolution

When a document type changes (e.g., a new field is added to the Rust struct):
- Old blocks still deserialize correctly (missing fields get their `Default` value)
- New fields are written on the next `update()`
- The schema block is updated with the new field descriptors

**The deserialization strategy:** Tolerant. Missing fields use `Default::default()`. Extra fields in the stored bytes (from a newer schema version writing to an older reader) are silently ignored.

---

## 6. Path Validation

All paths used by the typed document system must satisfy:

| Rule | Reason |
|---|---|
| Must start with `/` | Consistent with Merkle Index convention |
| Must not contain null bytes (`\0`) | Path strings are passed to FFI in some platforms |
| Must not exceed 1024 characters | Prevents index bloat and DoS |
| Must not contain relative path segments (`.` or `..`) | Prevents path traversal and canonicalization exploits |
| Must not contain reserved segments starting with `.akshara.` | Reserved for system metadata (schema, main document) |

Invalid paths return `Error::InvalidPath`.

---

## 7. Design Decisions

### 7.1 Why a derive macro instead of a manual trait impl

Manual implementation of the `AksharaDocument` trait would be error-prone: the developer must correctly map field paths, block modes, and lazy annotations. The derive macro guarantees consistency between the struct definition and the SDK's understanding of it.

### 7.2 Why `insert_document` is separate from `insert`

`insert()` writes raw bytes directly to a path. `insert_document()` decomposes a typed document into separate fields, invokes layout block adapters, structures sub-indices, writes the schema metadata, and maps the main struct content to the reserved `.akshara.document` leaf to avoid path conflicts. Keeping them separate avoids coupling the low-level byte store to schema-level logic.

### 7.3 Why `#[collection]` uses fractional indexing

Fractional indexing preserves insertion order without re-CIDing siblings. Array-index-based approaches (0, 1, 2) require renumbering every element after an insertion, which changes every CID and invalidates sync state. Fractional indexing creates new indices between existing ones without touching neighbors.

### 7.4 Dynamic Field-Level Loading `[Planned for v0.3+]`
For extremely large documents where downloading or deserializing the entire document is inefficient, the SDK will support querying a single field directly from its path coordinates in the Merkle Index tree, without loading the parent document struct:

```rust
impl Graph {
    /// Retrieve a single field of a structured document without loading the parent struct.
    pub async fn get_document_field<T, F>(&self, doc_path: &str, field_path: &str) -> Result<F, Error>
    where
        T: AksharaDocument,
        F: for<'de> Deserialize<'de>;
}
```

---

## 8. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `AksharaDocument` trait + derive | §1 | [Client & Graph](./client-and-graph.md) |
| `#[block]`, `#[collection]`, `#[chunked]`, `#[collaborative_text]` | §2 | [Sync](./sync.md) |
| `LazyField<T>` | §3 | [Sync](./sync.md), [Audit](./audit.md) |
| Schema metadata in index | §5 | [Sync](./sync.md) |
| Path validation | §6 | [Client & Graph](./client-and-graph.md), [Errors](./errors.md) |

---

**Certified by:**  
*The Akshara Council of One*
