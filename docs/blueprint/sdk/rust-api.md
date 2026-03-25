# SDK Rust API Specification

This document defines the high-level Rust interface for `akshara`. This is the canonical "Spec" we use to implement the platform's Layer 1 logic.

---

## 1. The Entry Point: `Client`

The `Client` manages the user's identity, vault, and graph access.

```rust
pub struct Client {
    // Internal: vault, store, staging
}

impl Client {
    /// Initializes the client with OS keychain vault.
    pub async fn init(config: ClientConfig) -> Result<Self, Error>;

    /// Creates a brand new Graph.
    pub async fn create_graph(&self) -> Result<Graph, Error>;

    /// Opens an existing Graph by its Lakshana.
    pub async fn open_graph(&self, lakshana: &str) -> Result<Graph, Error>;

    /// Lists all graphs the user has access to.
    pub async fn list_graphs(&self) -> Result<Vec<GraphSummary>, Error>;

    /// Synchronizes all graphs with the relay.
    pub async fn sync(&self) -> Result<SyncReport, Error>;
}
```

## 2. Working with Data: `Graph`

The `Graph` is the primary interface for reading and writing data.

```rust
pub struct Graph {
    // Internal: graph_id, graph_key, vault reference
}

impl Graph {
    /// Returns the graph's unique identifier.
    pub fn id(&self) -> GraphId;

    /// Inserts new content at a path (staged, not sealed).
    pub async fn insert(&self, path: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Updates existing content at a path (staged, not sealed).
    pub async fn update(&self, path: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Deletes content at a path (staged, not sealed).
    pub async fn delete(&self, path: &str) -> Result<(), Error>;

    /// Seals all staged operations into the Merkle-DAG.
    pub async fn seal(&self) -> Result<SealReport, Error>;

    /// Reads content from a path.
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, Error>;

    /// Checks if content exists at a path.
    pub async fn exists(&self, path: &str) -> Result<bool, Error>;

    /// Lists all paths with the given prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Error>;

    /// Synchronizes this graph with the relay.
    pub async fn sync(&self) -> Result<SyncReport, Error>;
}
```

## 3. Staging → Sealing Pipeline

The SDK buffers operations and seals them atomically:

```rust
// Stage operations (not persisted yet)
graph.insert("/doc1", b"Hello".to_vec()).await?;
graph.insert("/doc2", b"World".to_vec()).await?;

// Seal commits everything atomically
let report = graph.seal().await?;
println!("Sealed {} bytes in {} blocks", 
    report.bytes_sealed, report.blocks_created);
```

**What happens during seal():**
1. Fetch staged operations
2. Load current state from latest manifest (CRDT merge)
3. Apply staged operations to state
4. Create blocks for each path
5. Build Merkle-Index tree with fractional indexing
6. Create and sign manifest
7. Persist to store

---

## 4. Configuration

```rust
pub struct ClientConfig {
    pub vault: VaultConfig,
    pub tuning: TuningConfig,
}

pub enum VaultConfig {
    Platform,      // macOS Keychain / iOS Secure Enclave
    Ephemeral,     // Testing only (in-memory)
    Custom { backend: Arc<dyn Vault> },
}

pub struct TuningConfig {
    pub seal_idle_timeout: Duration,   // Default: 5s
    pub seal_op_threshold: usize,      // Default: 100 ops
    pub seal_size_threshold: usize,    // Default: 10MB
    pub max_block_size: usize,         // Default: 1MB
}
```

---

## 5. Error Handling

```rust
pub enum Error {
    InvalidMnemonic(String),
    Vault(VaultError),
    Storage(StorageError),
    GraphNotFound(GraphId),
    PathNotFound(String),
    NothingToSeal,
    SyncFailed(String),
    Protocol(AksharaError),
    Internal(String),
}
```

---

**Last Updated:** 2026-03-24
**Status:** Implemented in `akshara` v0.1.0-alpha.1
