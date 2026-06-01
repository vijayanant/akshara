# Spec 1: Client, Graph, and Flush

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Errors](./errors.md), [Typed Documents](./typed-documents.md), [Sync](./sync.md)

---

## Scope

This spec defines:
- `Client` — the entry point
- `ClientConfig` — initialization configuration
- `Vault` trait — key storage abstraction
- `Graph` handle — the primary working interface
- `flush()` — explicit seal operation
- Auto-commit behavior
- Basic read/write: `insert()`, `push()`, `get()`, `load()`, `delete()`

It does **not** cover: sync transport (see [Sync](./sync.md)), capability grants (see [Access Control](./access-control.md)), error variants (see [Errors](./errors.md)), derive macros (see [Typed Documents](./typed-documents.md)).

---

## 1. Client

### 1.1 `Client`

```rust
pub struct Client { /* opaque */ }
```

`Client` is the entry point. It manages:
- A vault for identity and key storage
- A storage backend for blocks and manifests
- A staging buffer for write operations
- The user's root signing identity

It does **not** hold secret keys in memory beyond what the `Vault` exposes during a cryptographic operation. The vault is locked and cleared immediately after each operation.

### 1.2 `ClientConfig`

```rust
pub struct ClientConfig {
    vault: VaultConfig,
    storage: StorageConfig,
    tuning: TuningConfig,
}
```

### 1.3 `VaultConfig`

```rust
pub enum VaultConfig {
    /// OS keychain: macOS Keychain, iOS Secure Enclave, Windows Credential Locker
    Platform,

    /// In-memory, for testing only. Secret material is Zeroized on drop.
    Ephemeral,
}
```

A `Custom` variant is deliberately omitted. Vault implementations are platform-specific and the SDK ships the two that cover production and testing. If a custom vault is needed, the developer implements the `Vault` trait directly (see §1.5).

### 1.4 `StorageConfig`

```rust
pub enum StorageConfig {
    /// SQLite-backed persistent store at the given path.
    Sqlite { path: PathBuf },

    /// In-memory store, for testing and ephemeral use.
    InMemory,
}
```

### 1.5 `TuningConfig`

```rust
pub struct TuningConfig {
    /// Duration of idle time before auto-flush triggers.
    /// Default: 5 seconds.
    pub auto_flush_timeout: Duration,

    /// Maximum number of staged operations before auto-flush triggers.
    /// Default: 100.
    pub auto_flush_op_threshold: usize,

    /// Maximum total bytes of staged data before auto-flush triggers.
    /// Default: 10 MB.
    pub auto_flush_size_threshold: usize,

    /// Maximum size of a single block. Payloads exceeding this are
    /// rejected unless the field is annotated with #[chunked].
    /// Default: 1 MB.
    pub max_block_size: usize,
}

impl Default for TuningConfig { .. }
```

### 1.6 `Client::init`

```rust
impl Client {
    pub async fn init(config: ClientConfig) -> Result<Client, Error>;
}
```

**Behavior:**

1. Creates the vault from `VaultConfig`
2. Calls `vault.initialize(None)` — generates a 24-word mnemonic if none exists
3. Derives the root signing identity from the vault
4. Creates the storage backend from `StorageConfig`
5. Creates an empty staging buffer
6. Returns the `Client`

**Errors:**

| Variant | Condition |
|---|---|
| `VaultError` | Vault creation fails (keychain unavailable, etc.) |
| `IdentityError` | Mnemonic generation or derivation fails |
| `StorageError` | Storage creation fails (disk full, path not writable) |

### 1.7 `Client::create_graph`

```rust
impl Client {
    pub async fn create_graph(&self) -> Result<Graph, Error>;
}
```

**Behavior:**

1. Generates a random `GraphId`
2. Derives a `GraphKey` from the vault using the `GraphId` (Branch 2 — Secret)
3. Creates an empty Merkle Index in the staging buffer
4. Creates a genesis manifest signed by the client's shadow identity for this graph
5. Returns a `Graph` handle

**Invariants:**

- The graph key is **never** stored in the `Graph` struct beyond the scope of a single cryptographic operation. It is derived from the vault on demand.
- The genesis manifest's `identity_anchor` is `ManifestId::null()` (the rebirth invariant).

### 1.8 `Client::open_graph`

```rust
impl Client {
    pub async fn open_graph(&self, lakshana: &str) -> Result<Graph, Error>;
}
```

**Behavior:**

1. Parses the `Lakshana` string
2. Resolves the `GraphId` (deterministic truncation for v0.1; relay resolution in v0.2)
3. Derives the `GraphKey` from the vault
4. Verifies the graph exists in local storage (heads check)
5. Returns a `Graph` handle

**Errors:**

| Variant | Condition |
|---|---|
| `GraphNotFound` | No heads exist locally for this graph |
| `InvalidLakshana` | The lakshana string fails to parse |

### 1.9 `Client::list_graphs`

```rust
impl Client {
    pub async fn list_graphs(&self) -> Result<Vec<GraphSummary>, Error>;
}
```

**Behavior:** Scans the storage backend for all graphs with local heads and returns summaries.

```rust
pub struct GraphSummary {
    pub graph_id: GraphId,
    pub lakshana: String,
    pub manifest_count: usize,
    pub last_flushed: Option<DateTime<Utc>>,
}
```

### 1.10 `Client::forget_graph`

```rust
impl Client {
    pub async fn forget_graph(&self, graph_id: GraphId) -> Result<(), Error>;
}
```

**Behavior:** Removes all local heads, manifests, and blocks for the given graph from storage. Does not affect remote copies. The graph key remains in the vault (it can be re-derived).

**Warning:** This is destructive. The method name is deliberately strong.

---

## 2. Vault

### 2.1 `Vault` Trait

```rust
#[async_trait]
pub trait Vault: Send + Sync {
    /// Initialize the vault. If mnemonic is None, generates a new one.
    /// Returns the mnemonic string if newly generated (for display to user).
    async fn initialize(&self, mnemonic: Option<String>) -> Result<Option<String>, Error>;

    /// Returns the root signing public key.
    async fn get_identity(&self) -> Result<PublicIdentity, Error>;

    /// Derives a graph-specific symmetric key (Branch 2 — Secret).
    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey, Error>;

    /// Signs data using the executive branch (Branch 1) for the given graph.
    /// The secret key is loaded, used, and zeroized in a single critical section.
    async fn sign_for_graph(&self, graph_id: &GraphId, message: &[u8]) -> Result<Signature, Error>;

    /// Returns the latest identity anchor (ManifestId of the identity graph).
    fn latest_identity_anchor(&self) -> ManifestId;

    /// Clears all secret material from the vault.
    async fn reset(&self) -> Result<(), Error>;
}
```

**Invariants:**

- Secret keys are **never** held beyond the scope of a single signing/derivation operation
- All secret material is wrapped in `Zeroizing<T>`
- `sign_for_graph` uses a shadow identity isolated to the graph (prevents cross-graph signature linking)

---

## 3. Graph

### 3.1 `Graph` Handle

```rust
pub struct Graph { /* opaque */ }
```

`Graph` is a handle to a single graph. It is `Clone` — cloning creates a new handle to the same graph (shared client, shared storage, shared staging).

The handle does **not** hold the graph key in memory. The key is derived from the vault on each cryptographic operation.

### 3.2 `Graph::id`

```rust
impl Graph {
    pub fn id(&self) -> GraphId;
}
```

### 3.3 `Graph::flush`

```rust
impl Graph {
    pub async fn flush(&self) -> Result<FlushReport, Error>;
}
```

**Behavior:**

1. Fetches all staged operations from the staging buffer
2. If empty, returns `Error::NothingToFlush`
3. Coalesces operations by path (last-write-wins)
4. Loads the current graph state from the latest manifest (CRDT-style merge)
5. Applies coalesced operations — creates blocks, builds index tree
6. Derives a shadow identity for this graph
7. Creates and signs a new manifest, anchored to `vault.latest_identity_anchor()`
8. Persists blocks and manifest to storage
9. Clears committed operations from staging (timestamp ≤ flush timestamp)
10. Returns `FlushReport`

```rust
pub struct FlushReport {
    pub manifest_id: ManifestId,
    pub blocks_created: usize,
    pub bytes_sealed: u64,
    pub operations_coalesced: usize,
}
```

**Atomicity:**

- Flush is **all-or-nothing**. If it fails at any step, staging is NOT cleared and no blocks are written.
- A crash during flush leaves staging intact. The next flush re-applies the same operations (idempotent for staged writes).
- If the same path was staged twice and the first flush succeeds, the second flush sees the updated state from the manifest.

**Invariants:**

- Every block is encrypted with the graph key and signed by the graph's shadow identity
- The manifest's `content_root` points to the Merkle Index root
- Parent manifests are preserved in the `parents` field (DAG edges)

### 3.4 Auto-Flush

The SDK maintains an internal idle timer per graph. Auto-flush triggers when **any** of these conditions are met:

| Condition | Default | Configurable via |
|---|---|---|
| Idle timeout | 5 seconds | `tuning.auto_flush_timeout` |
| Operation count | 100 ops | `tuning.auto_flush_op_threshold` |
| Total staged size | 10 MB | `tuning.auto_flush_size_threshold` |

Auto-flush is **not** guaranteed — it is a best-effort background operation. If the application shuts down before auto-flush triggers, staged operations are preserved in the staging store and flushed on next `Client::init` (provided the staging store is persistent; `InMemoryStagingStore` loses data on shutdown).

**The developer can disable auto-flush** by setting all thresholds to their maximum values. This is not recommended for production use.

### 3.5 `Graph::insert`

```rust
impl Graph {
    pub async fn insert(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<(), Error>;
}
```

**Behavior:**

1. Creates a `StagedOperation::Insert { path, data: data.into(), timestamp }`
2. Pushes to the staging buffer
3. Returns immediately (does not flush)

**Path validation:**

- Path must start with `/`
- Path must not contain null bytes
- Path must not contain relative segments (`.` or `..`)
- Path must not contain segments starting with `.akshara.`
- Path must not exceed 1024 characters

**Errors:**

| Variant | Condition |
|---|---|
| `InvalidPath` | Path fails validation |
| `StagingError` | Write to staging fails |

### 3.6 `Graph::update`

```rust
impl Graph {
    pub async fn update(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<(), Error>;
}
```

**Behavior:** Same as `insert`, but creates a `StagedOperation::Update`. During flush, updates coalesce over inserts at the same path (last-write-wins). If the path already exists in the manifest, the new block's parent is the existing block's CID.

### 3.7 `Graph::delete`

```rust
impl Graph {
    pub async fn delete(&self, path: &str) -> Result<(), Error>;
}
```

**Behavior:** Creates a `StagedOperation::Delete { path, timestamp }`. During flush, deletes create a **tombstone block** at the path. The tombstone is an empty `BlockContent` with `BlockType::AksharaDataV1` and a metadata field marking it as deleted. The path is no longer visible in `list()` or `get()` queries.

**Important:** Deletion is a **logical** operation, not a physical one. The data block still exists in the store. The tombstone simply marks it as deleted in the current state.

**Errors:**

| Variant | Condition |
|---|---|
| `InvalidPath` | Path fails validation |

### 3.8 `Graph::get`

```rust
impl Graph {
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, Error>;
}
```

**Behavior:**

1. Gets the latest manifest head from the graph
2. Walks the Merkle Index from `content_root` to resolve `path`
3. At each step, decrypts the index block with the graph key and verifies the block's signature
4. When the target block is reached, decrypts it with the graph key
5. Returns the decrypted payload bytes

**Errors:**

| Variant | Condition |
|---|---|
| `PathNotFound` | Path does not exist in the current manifest |
| `Internal` | Decryption/Verification fails |

### 3.9 `Graph::insert_document`

```rust
impl Graph {
    pub async fn insert_document<D: AksharaDocument>(&self, path: &str, doc: &D) -> Result<(), Error>;
}
```

**Behavior:**

1. Serializes `doc` to DAG-CBOR bytes.
2. Stages a `StagedOperation::Insert` to store the main document at `path/.akshara.document`.
3. Serializes `D::schema()` and stages an insert at `path/.akshara.schema`.
4. Invokes `doc.serialize_fields()` to run layout block adapters for fields requiring independent block layouts (collections, chunks, collaborative texts), receiving their resolved block addresses.
5. Stages a `StagedOperation::Link` for each adapter-resolved address pointing directly to the generated field layout root (e.g. `path/field_name`).

### 3.10 `Graph::get_document`

```rust
impl Graph {
    pub async fn get_document<D: AksharaDocument>(&self, path: &str) -> Result<D, Error>;
}
```

**Behavior:**

1. Gets the latest manifest head and walks the Merkle Index to resolve `/path/.akshara.document`.
2. Fetches and decrypts the main document block, deserializing the main fields into the typed struct.
3. Invokes `doc.deserialize_fields()` to walk the sub-index nodes under the manifest content root and reassemble any adapter-managed fields (collections, chunks, collaborative texts) or lazy fields using their resolved block addresses.
4. Returns the fully reassembled typed document.

### 3.10 `Graph::exists`

```rust
impl Graph {
    pub async fn exists(&self, path: &str) -> Result<bool, Error>;
}
```

**Behavior:** Walks the Merkle Index to check if `path` exists and is not a tombstone. Returns `false` for deleted paths.

### 3.11 `Graph::list`

```rust
impl Graph {
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Error>;
}
```

**Behavior:** Walks the Merkle Index from `prefix` (or root if empty) and collects all non-tombstone paths. Does NOT fetch block data — only returns paths.

### 3.12 `Graph::history`

```rust
impl Graph {
    pub async fn history<T>(&self, path: &str) -> Result<Vec<DocumentVersion<T>>, Error>
    where
        T: AksharaDocument;
}
```

**Behavior:**

1. Walks the manifest chain from current head back to genesis
2. For each manifest, resolves `path` in its index tree
3. If found (and not tombstoned in that manifest), decrypts and deserializes the block
4. Returns a vector of versions in chronological order (oldest first)

```rust
pub struct DocumentVersion<T> {
    pub value: T,
    pub block_id: BlockId,
    pub manifest_id: ManifestId,
    pub authored_at: DateTime<Utc>,  // From manifest header
    pub author_fingerprint: String,  // Obfuscated path hash of signer
}
```

**Performance:** This is O(M × D) where M is the number of manifests and D is the path depth. For long-lived graphs this can be expensive. Pagination is planned for v0.2.

### 3.13 `Graph::fetch_blob`

```rust
impl Graph {
    /// Fetch raw bytes at a path without deserializing into a typed document.
    ///
    /// This is used for large binary data (files, images, PDFs) that the
    /// developer wants to handle directly rather than deserialize into a struct.
    /// For chunked fields, this automatically reassembles all chunks.
    pub async fn fetch_blob(&self, path: &str) -> Result<Vec<u8>, Error>;
}
```

**Behavior:**

1. Walks the Merkle Index to resolve `path`
2. If the path points to a `#[chunked]` field, fetches and reassembles all chunks
3. If the path point to a `#[block]` field, fetches the single block
4. Decrypts with the graph key
5. Returns raw bytes (no deserialization)

**Errors:**

| Variant | Condition |
|---|---|
| `PathNotFound` | Path does not exist |
| `DecryptionError` | Block cannot be decrypted |
| `SignatureVerificationError` | Block signature is invalid |

### 3.14 `Graph::sync_scope`

See [Sync](./sync.md).

### 3.15 `Graph::grant_access`

See [Access Control](./access-control.md).

---

## 4. Cross-Graph References

### 4.1 `GraphRef`

```rust
pub struct GraphRef {
    /// The target graph's lakshana.
    target_lakshana: Lakshana,

    /// The path within the target graph.
    target_path: String,
}

impl GraphRef {
    /// Create a reference to a path in another graph.
    ///
    /// This does NOT fetch data — it is a lightweight handle.
    pub fn new(lakshana: &str, path: &str) -> Self;

    /// Resolve the reference and load the target document.
    ///
    /// This opens the target graph (if not already open), walks its
    /// Merkle Index, and deserializes the value.
    pub async fn resolve<T>(&self, client: &Client) -> Result<T, Error>
    where
        T: AksharaDocument;

    /// Resolve the reference and fetch raw bytes (for chunked/blob data).
    pub async fn resolve_blob(&self, client: &Client) -> Result<Vec<u8>, Error>;

    /// Returns the Akshara URI for this reference.
    pub fn to_uri(&self) -> String;  // "akshara://{lakshana}/{path}"
}
```

**Behavior of `resolve()`:**

1. Checks if the target graph is already open in the client
2. If not, opens it via `client.open_graph(lakshana)`
3. Walks the target graph's Merkle Index to resolve `target_path`
4. Decrypts and deserializes into type `T`
5. Returns the typed value

**Errors:**

| Variant | Condition |
|---|---|
| `GraphNotFound` | Target graph is not accessible (no grant or not opened) |
| `AccessDenied` | Target graph requires a grant the client doesn't hold |
| `PathNotFound` | Path doesn't exist in the target graph |
| `DecryptionError` | Block can't be decrypted (wrong key) |
| `DeserializationError` | Bytes can't be parsed into type `T` |

### 4.2 Creating References

```rust
impl Graph {
    /// Create a reference to a path within this graph.
    pub fn link(&self, path: &str) -> GraphRef;
}
```

**Usage:**

```rust
// Create a reference from one graph to another
let consent_ref = patient_graph.link("consents/surgery-001");

// Store the reference in another graph
legal_graph.insert("case-001/patient-consent", &consent_ref).await?;

// Resolve it later
let consent: ConsentForm = consent_ref.resolve(&client).await?;
```

---

## 5. Staging Store

### 5.1 `StagingStore` Trait

```rust
#[async_trait]
pub trait StagingStore: Send + Sync {
    async fn stage_operation(&self, op: StagedOperation) -> Result<(), Error>;
    async fn fetch_pending(&self) -> Result<Vec<StagedOperation>, Error>;
    async fn clear_committed(&self, up_to_timestamp: u64) -> Result<(), Error>;
}
```

All methods take `&self` (not `&mut self`) because the staging store is shared across `Clone`d `Graph` handles via `Arc<Mutex<Box<dyn StagingStore>>>`. Interior mutability is used.

### 5.2 `StagedOperation`

```rust
pub enum StagedOperation {
    Insert {
        path: String,
        data: Vec<u8>,
        timestamp: u64,
    },
    Update {
        path: String,
        data: Vec<u8>,
        timestamp: u64,
    },
    Link {
        path: String,
        address: Address,
        timestamp: u64,
    },
    Delete {
        path: String,
        timestamp: u64,
    },
}
```

### 5.3 Coalescing

During flush, operations are coalesced by path:

```
Insert("/a", v1)  +  Update("/a", v2)  →  Update("/a", v2)
Insert("/a", v1)  +  Delete("/a")       →  Delete("/a")
Update("/a", v2)  +  Update("/a", v3)  →  Update("/a", v3)
Insert("/a", v1)  +  Insert("/a/b", v) →  both kept (different paths)
```

Coalescing uses last-write-wins by timestamp. For same-timestamp operations, the order they were staged is preserved.

### 5.4 Default Implementations

| Implementation | Persistence | Use Case |
|---|---|---|
| `InMemoryStagingStore` | Lost on shutdown | Testing, ephemeral |
| `SqliteStagingStore` | Persistent (same SQLite file as storage) | Production |

The `SqliteStagingStore` ensures that staged operations survive application crashes and are flushed on next startup.

---

## 5. Design Decisions

### 5.1 Why `flush()` instead of `seal()`

`seal()` exposes the Merkle-DAG mechanic. `flush()` communicates intent: "persist my writes now." The developer doesn't need to understand manifests, CIDs, or Merkle trees to use the API correctly.

### 5.2 Why no `Graph` name parameter

`create_graph()` does not accept a name. Graph names are metadata that should live in the developer's own application database, not in the Akshara protocol. The SDK has no need for human-readable identifiers. The `GraphSummary` type exposes a `lakshana` for user-facing display, but the protocol uses `GraphId` exclusively.

### 5.3 Why collection insertion is handled via adapters rather than a `push` method

Instead of exposing a `push()` method directly on the low-level byte-oriented `Graph` handle, array/list insertion is handled automatically by marking a document field with `#[collection]`. This delegates collection layout and fractional indexing directly to the `CollectionBlockAdapter` during `insert_document` / `get_document` cycles, keeping the raw `Graph` API clean and free of schema-specific concepts.

### 5.4 Why `delete` creates a tombstone instead of removing data

Akshara graphs are append-only DAGs. Blocks are immutable. Deletion cannot remove a block — it can only add a new block that marks the path as deleted. This preserves the full history. If physical deletion is needed (regulatory compliance), the storage backend can implement garbage collection of unreachable blocks, but this is outside the SDK's scope.

### 5.5 Why auto-flush is best-effort

Guaranteeing auto-flush would require a background task that blocks shutdown until it completes. This creates deadlock risks and makes `Client` harder to test. Best-effort with persistent staging is safer: staged operations survive shutdown and flush on next startup.

---

## 6. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `Client`, `ClientConfig`, `TuningConfig` | §1 | All specs |
| `Vault` trait | §2 | [Access Control](./access-control.md) |
| `Graph::flush`, auto-commit | §3.3–3.4 | [Typed Documents](./typed-documents.md), [Audit](./audit.md) |
| `Graph::insert`, `delete` | §3.5, 3.7 | [Typed Documents](./typed-documents.md) |
| `Graph::get` | §3.8 | [Typed Documents](./typed-documents.md), [Audit](./audit.md) |
| `Graph::insert_document`, `get_document` | §3.9, 3.10 | [Typed Documents](./typed-documents.md) |
| `GraphRef`, `resolve()`, `link()` | §4 | [Typed Documents](./typed-documents.md), [Audit](./audit.md) |
| `StagingStore`, `StagedOperation` | §5 | [Typed Documents](./typed-documents.md) |
| `Error` variants | Referenced throughout | [Errors](./errors.md) |

---

**Certified by:**  
*The Akshara Council of One*
