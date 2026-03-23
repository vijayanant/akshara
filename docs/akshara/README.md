---
title: "The Akshara API"
version: "0.1.0-alpha.1"
status: "Draft"
date: 2026-03-23
---

# The Akshara API

**The developer-facing API for building applications on Akshara.**

---

## 1. Vision

### What Is This?

The `akshara` crate is the **primary interface** for application developers building on Akshara. It abstracts the cryptographic and protocol complexity of `akshara-aadhaara` into a simple, ergonomic API.

### Mental Model

```
┌─────────────────────────────────────────────────────────────┐
│  Your Application                                           │
│  (Notes app, Healthcare platform, Legal tech, etc.)         │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ uses
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  akshara (this crate)                                       │
│  - Client::init()                                           │
│  - Graph::insert("/path", data)                             │
│  - Graph::seal()                                            │
│  - Graph::sync()                                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ built on
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  akshara-aadhaara (protocol kernel)                         │
│  - Block, Manifest, CID                                     │
│  - SecretIdentity, GraphKey                                 │
│  - Reconciler, GraphStore                                   │
└─────────────────────────────────────────────────────────────┘
```

### Design Philosophy

| Principle | Description |
|-----------|-------------|
| **You Handle Plaintext, We Handle Vault** | Developers work with strings/bytes. Encryption, signing, key management are automatic. |
| **Offline is Default** | All writes are local first. Sync is explicit, background, and resumable. |
| **Paths, Not CIDs** | Humans think `/notes/meeting.md`. The API maps paths to CIDs internally. |
| **Seal is Explicit** | Buffering is automatic, but committing to the DAG is a conscious choice. |
| **Conflicts are Events** | Concurrent edits create branches. The app decides merge strategy. |

---

## 2. Quick Start

```rust
use akshara::{Client, ClientConfig};

// 1. Initialize the client
let config = ClientConfig::new()
    .with_sqlite_storage("./akshara.db")
    .with_keychain_vault();  // MacOS Keychain, iOS Secure Enclave, etc.

let client = Client::init(config).await?;

// 2. Create or open a graph
let notes = client.create_graph("my-notes").await?;
// or
let shared = client.open_graph(lakshana).await?;

// 3. Write data (buffered, not yet sealed)
notes.insert("meeting-notes", b"Today we discussed...").await?;
notes.update("/drafts/proposal", new_content).await?;

// 4. Seal the changes (creates Merkle-DAG update)
notes.seal().await?;

// 5. Sync with relay (or peer)
client.sync().await?;
```

---

## 3. Core Concepts

### 3.1 The Client

`Client` is the entry point. It manages:

- **Identity** — 24-word mnemonic, key derivation
- **Vault** — Secure key storage (Keychain, Secure Enclave, etc.)
- **Storage** — SQLite, IndexedDB, or custom backend
- **Sync** — Background reconciliation with relays/peers

```rust
pub struct Client {
    identity: IdentityManager,
    vault: Box<dyn Vault>,
    store: Box<dyn GraphStore>,
    sync: SyncOrchestrator,
}
```

### 3.2 The Graph Handle

`Graph` is your working interface to a single graph:

```rust
pub struct Graph {
    graph_id: GraphId,
    graph_key: GraphKey,
    staging: StagingStore,
    aadhaara: AadhaaraHandle,  // Internal bridge to protocol layer
}
```

**Key operations:**

- `insert(path, data)` — Add new content
- `update(path, data)` — Replace existing content
- `delete(path)` — Mark content as deleted
- `get(path)` — Read content
- `seal()` — Commit staged operations to DAG
- `sync()` — Sync with relay/peer

### 3.3 Staging → Sealing Pipeline

This is the **core innovation** of the `akshara` crate.

```
Developer Calls                 Internal Pipeline
─────────────────               ─────────────────
insert("/doc", "A")    ──→      StageOperation(Insert)
insert("/doc2", "B")   ──→      StageOperation(Insert)
update("/doc", "C")    ──→      StageOperation(Update)  ← coalesces with first insert
                                │
seal()                 ──→      1. Fetch pending operations
                                2. Coalesce by path
                                3. Chunk large payloads (>1MB)
                                4. Assign fractional indices
                                5. Build Merkle-Index tree
                                6. Create & sign Manifest
                                7. Persist to store
                                8. Clear staging
```

**Why this matters:**

- Developers think in **operations**, not blocks
- Multiple ops → single manifest (efficient)
- Automatic deduplication and chunking
- No need to understand Merkle-DAG internals

---

## 4. API Reference

### 4.1 Client Initialization

```rust
pub struct ClientConfig {
    storage: StorageConfig,
    vault: VaultConfig,
    relay: Option<RelayConfig>,
}

pub enum StorageConfig {
    Sqlite { path: PathBuf },
    IndexedDb { name: String },  // WASM only
    Custom { backend: Box<dyn GraphStore> },
}

pub enum VaultConfig {
    Keychain,          // MacOS/iOS
    SecureEnclave,     // iOS with biometrics
    Ephemeral,         // Testing only (memory)
    Custom { vault: Box<dyn Vault> },
}

impl Client {
    pub async fn init(config: ClientConfig) -> Result<Self, Error>;
    
    pub async fn create_graph(&self, name: &str) -> Result<Graph, Error>;
    pub async fn open_graph(&self, lakshana: &str) -> Result<Graph, Error>;
    pub async fn list_graphs(&self) -> Result<Vec<GraphSummary>, Error>;
    
    pub async fn sync(&self) -> Result<SyncReport, Error>;
    pub async fn sync_graph(&self, graph_id: GraphId) -> Result<SyncReport, Error>;
}
```

### 4.2 Graph Operations

```rust
impl Graph {
    // === Staged Writes ===
    pub async fn insert(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<(), Error>;
    pub async fn update(&self, path: &str, data: impl Into<Vec<u8>>) -> Result<(), Error>;
    pub async fn delete(&self, path: &str) -> Result<(), Error>;
    
    // === Reads ===
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, Error>;
    pub async fn exists(&self, path: &str) -> Result<bool, Error>;
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Error>;
    
    // === Sealing ===
    pub async fn seal(&self) -> Result<SealReport, Error>;
    pub async fn seal_batch(&self, ops: Vec<StagedOperation>) -> Result<SealReport, Error>;
    
    // === Sync ===
    pub async fn sync(&self) -> Result<SyncReport, Error>;
    
    // === Sharing ===
    pub async fn share_with(&self, recipient_pubkey: &SigningPublicKey) -> Result<(), Error>;
    pub async fn revoke_access(&self, recipient_pubkey: &SigningPublicKey) -> Result<(), Error>;
    
    // === Conflict Resolution ===
    pub async fn get_conflicts(&self) -> Result<Vec<Conflict>, Error>;
    pub async fn resolve_conflict(&self, conflict: Conflict, strategy: MergeStrategy) -> Result<(), Error>;
}
```

### 4.3 Reports

```rust
pub struct SealReport {
    pub manifest_id: ManifestId,
    pub blocks_created: usize,
    pub bytes_sealed: u64,
    pub operations_coalesced: usize,
}

pub struct SyncReport {
    pub graphs_synced: usize,
    pub manifests_received: usize,
    pub blocks_received: usize,
    pub bytes_transferred: u64,
    pub conflicts_detected: usize,
}

pub struct Conflict {
    pub graph_id: GraphId,
    pub path: String,
    pub heads: Vec<ManifestId>,  // Concurrent heads
    pub strategy: Option<MergeStrategy>,
}

pub enum MergeStrategy {
    KeepLatest,       // Lexicographically lower CID wins
    KeepMine,         // Local head wins
    KeepTheirs,       // Remote head wins
    Manual { resolver: Box<dyn ConflictResolver> },
}
```

---

## 5. Implementation Details

### 5.1 Staging Store

**Purpose:** Buffer operations before sealing.

```rust
pub trait StagingStore: Send + Sync {
    async fn stage_operation(&mut self, op: StagedOperation) -> Result<(), Error>;
    async fn fetch_pending(&self) -> Result<Vec<StagedOperation>, Error>;
    async fn clear_committed(&mut self, up_to: ManifestId) -> Result<(), Error>;
}

pub enum StagedOperation {
    Insert { path: String, data: Vec<u8>, timestamp: u64 },
    Update { path: String, data: Vec<u8>, timestamp: u64 },
    Delete { path: String, timestamp: u64 },
}
```

**Default Implementation:** SQLite-backed with in-memory cache.

### 5.2 Coalescing Logic

```rust
fn coalesce(ops: Vec<StagedOperation>) -> Vec<StagedOperation> {
    let mut by_path: BTreeMap<String, StagedOperation> = BTreeMap::new();
    
    for op in ops {
        match op {
            Insert { path, data, .. } => {
                by_path.insert(path, Insert { path, data, .. });
            }
            Update { path, data, .. } => {
                // Update replaces any prior insert/update at same path
                by_path.insert(path, Update { path, data, .. });
            }
            Delete { path, .. } => {
                // Delete clears any prior ops at same path
                by_path.insert(path, Delete { path, .. });
            }
        }
    }
    
    by_path.into_values().collect()
}
```

### 5.3 Chunking Strategy

```rust
const MAX_BLOCK_SIZE: usize = 1024 * 1024;  // 1MB

async fn chunk_data(
    data: &[u8],
    graph_key: &GraphKey,
    identity: &SecretIdentity,
    store: &mut dyn GraphStore,
) -> Result<Address, Error> {
    if data.len() <= MAX_BLOCK_SIZE {
        // Single block
        let block = Block::new(data, "data", vec![], graph_key, identity).await?;
        store.put_block(&block).await?;
        return Ok(Address::from(block.id()));
    }
    
    // Chunk into tree
    let mut chunks = Vec::new();
    for chunk in data.chunks(MAX_BLOCK_SIZE) {
        let block = Block::new(chunk, "data", vec![], graph_key, identity).await?;
        store.put_block(&block).await?;
        chunks.push(block);
    }
    
    // Build index pointing to chunks
    let mut builder = IndexBuilder::new();
    for (i, block) in chunks.iter().enumerate() {
        builder.insert(&format!("chunk/{}", i), Address::from(block.id()))?;
    }
    let root_index = builder.build(store, identity, graph_key).await?;
    
    Ok(Address::from(root_index))
}
```

### 5.4 Fractional Indexing

```rust
fn assign_fractional_index(
    existing_keys: &[String],
    target_path: &str,
) -> String {
    // Find siblings
    let (prev, next) = find_neighbors(existing_keys, target_path);
    
    // Compute midpoint
    midpoint_string(prev, next)
}

fn midpoint_string(a: &str, b: &str) -> String {
    // ASCII midpoint algorithm
    // "a" + "b" → "am"
    // "am" + "b" → "ar"
    // etc.
}
```

### 5.5 Storage Backends

**SQLite (Primary):**

- Persistent, ACID-compliant
- Works on desktop, mobile, server
- Single file, no external dependencies

**IndexedDB (WASM):**

- Browser-based apps
- Quota-managed by browser
- Async-native

**In-Memory (Testing):**

- Ephemeral
- Fast tests
- No persistence

---

## 6. Error Handling

```rust
#[derive(Debug, Error)]
pub enum Error {
    // === Identity ===
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),
    
    // === Storage ===
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    
    #[error("Graph not found: {0}")]
    GraphNotFound(GraphId),
    
    // === Path Resolution ===
    #[error("Path not found: {0}")]
    PathNotFound(String),
    
    #[error("Cycle detected in index tree")]
    CycleDetected,
    
    // === Sealing ===
    #[error("Staging store empty, nothing to seal")]
    NothingToSeal,
    
    #[error("Chunking failed: {0}")]
    ChunkingFailed(String),
    
    // === Sync ===
    #[error("Sync failed: {0}")]
    SyncFailed(String),
    
    #[error("Conflict detected at path {0}")]
    ConflictDetected(String),
    
    // === Protocol (wrapped from aadhaara) ===
    #[error("Protocol error: {0}")]
    Protocol(#[from] akshara_aadhaara::AksharaError),
}
```

---

## 7. Security Considerations

### What This Crate Protects

| Threat | Mitigation |
|--------|------------|
| **Master seed exposure** | Seed never leaves Vault; only derived keys used |
| **Plaintext leakage** | Data encrypted before hitting storage |
| **Tampering** | All blocks verified on read (CID + signature) |
| **Unauthorized access** | Authority checked via `Auditor` before returning data |

### What This Crate Does NOT Protect

| Limitation | Impact |
|------------|--------|
| **Compromised host** | If attacker has memory access, they can read plaintext |
| **Vault implementation bugs** | Security depends on Vault (Keychain, etc.) |
| **Relay withholding data** | Relay can delay sync; can't forge data |

### Developer Responsibilities

1. **Protect the mnemonic** — Never log it, never transmit it
2. **Use secure Vault** — Don't use `Ephemeral` in production
3. **Handle conflicts** — Don't ignore `ConflictDetected` errors
4. **Validate input** — This crate validates structure, not semantics

---

## 8. Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| `insert()` | O(1) | Just stages operation |
| `seal()` | O(N log N) | N = pending ops; includes index rebuild |
| `get(path)` | O(D) | D = path depth (max 256) |
| `sync()` | O(M + K) | M = manifests, K = blocks to transfer |

### Tuning Parameters

```rust
pub struct ClientConfig {
    // === Staging ===
    pub seal_idle_timeout: Duration,  // Default: 5s
    pub seal_op_threshold: usize,     // Default: 100 ops
    pub seal_size_threshold: usize,   // Default: 10MB
    
    // === Chunking ===
    pub max_block_size: usize,        // Default: 1MB
    
    // === Sync ===
    pub max_heads_per_graph: usize,   // Default: 1024
    pub max_delta_size: usize,        // Default: 100,000 CIDs
}
```

---

## 9. Migration from `aadhaara`

If you've been using `akshara-aadhaara` directly:

### Before (aadhaara)

```rust
use akshara_aadhaara::{Block, Manifest, GraphKey, SecretIdentity, InMemoryStore};

let identity = SecretIdentity::generate(&mut rng);
let graph_key = identity.derive_graph_key(&graph_id)?;

let block = Block::new(graph_id, data, "data", vec![], &graph_key, &identity).await?;
store.put_block(&block).await?;

let manifest = Manifest::new(graph_id, block.id(), parents, anchor, &identity);
store.put_manifest(&manifest).await?;
```

### After (akshara)

```rust
use akshara::{Client, ClientConfig};

let client = Client::init(config).await?;
let graph = client.create_graph("my-graph").await?;

graph.insert("/path", data).await?;
graph.seal().await?;  // Creates block + manifest automatically
```

---

## 10. Future Extensions

### Planned for v0.3

- [ ] **Automatic background sealing** — Idle-timeout based
- [ ] **Conflict webhooks** — Callback on conflict detection
- [ ] **Streaming reads** — For large files
- [ ] **Query API** — SQL-like queries over graph content

### Planned for v0.4

- [ ] **Multi-graph transactions** — Atomic ops across graphs
- [ ] **Capability delegation** — Grant limited write access
- [ ] **Encrypted indexing** — Search without revealing content

### Under Discussion

- [ ] **GraphQL interface** — Query graphs with GraphQL
- [ ] **Reactive streams** — `graph.watch(path)` for live updates
- [ ] **Plugin system** — Custom coalescing strategies

---

## 11. References

- [Graph Model Specification](../specs/graph-model/README.md)
- [Identity Specification](../specs/identity/README.md)
- [Storage Specification](../specs/storage/README.md)
- [Aadhaara API Docs](../../aadhaara/README.md)
- [Blueprint: SDK Core Concepts](../blueprint/sdk/core-concepts.md)
- [Blueprint: SDK Rust API](../blueprint/sdk/rust-api.md)

---

**Last Updated:** 2026-03-23
**Status:** Draft — API subject to change during implementation
