---
title: "Storage Interface Specification"
subtitle: "The Decoupled GraphStore Trait and Persistent Adapters"
version: "0.1.0-alpha.3"
status: "Accepted"
date: "2026-06-04"
---

# Storage Interface Specification

## 1. Motivation

### The Problem
Previously, the `GraphStore` trait was directly coupled to high-level domain structures and cryptographic types, such as `Block`, `Manifest`, `PubKey`, and `PreKeyBundle`. This created several architectural issues:
- **Tight Coupling**: Database drivers had to compile against the core cryptographic and serialization libraries, forcing a change in the storage driver whenever a domain struct was modified.
- **Leaked Domain Knowledge**: Relays and cloud storage backends had to understand the internal schemas of the data they stored, violating the **Zero-Knowledge** principle of a blind relay.
- **Forward Secrecy Complexity**: To enforce Forward Secrecy (X3DH), one-time prekeys must be atomically retrieved and deleted. Implementing this at the database layer required the driver to parse CBOR blocks to find and remove individual keys, which is error-prone and slow.

### The Decoupled Solution
Akshara defines a fully decoupled **`GraphStore`** trait. The trait operates exclusively on **raw byte slices (`&[u8]`)** for storage payloads, and uses simple primitive identifiers (e.g., indexes and address slices) for partitioning.

All serialization/deserialization (using CBOR/DAG-CBOR) is handled in the trait's **default methods**, making the storage adapters "dumb" persistence engines that have zero knowledge of the underlying data structures.

```
┌─────────────────────────────────────────────────────────────┐
│  Akshara Domain Logic (Block, Manifest, PreKeyBundle)       │
└─────────────────────────────────────────────────────────────┘
                           │
                           │  CBOR (de)serialization
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  GraphStore Trait (Default Methods)                         │
└─────────────────────────────────────────────────────────────┘
                           │
                           │  Raw Bytes (&[u8] / Vec<u8>)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Storage Adapters (InMemoryStore, SqliteStore, etc.)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Core API: The `GraphStore` Trait

Defined in `akshara-aadhaara` core, the trait exposes low-level byte hooks for database adapters to override, and high-level typed interfaces for application use.

### 2.1 Low-Level Byte API
Database adapters must implement these asynchronous, non-blocking methods:

```rust
#[async_trait]
pub trait GraphStore: Send + Sync {
    // --- Content-Addressable Storage (CAS) ---
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError>;
    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError>;
    async fn put_manifest_bytes(&self, id: &ManifestId, graph_id: &GraphId, parents: &[ManifestId], data: &[u8]) -> Result<(), AksharaError>;
    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError>;

    // --- DAG Frontier / Heads ---
    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError>;

    // --- User Discovery / Lockboxes ---
    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError>;
    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError>;

    // --- Key Exchange (X3DH Session Prekeys) ---
    async fn put_prekey_bundle_bytes(&self, device_key: &[u8], data: &[u8]) -> Result<(), AksharaError>;
    async fn get_prekey_bundle_bytes(&self, device_key: &[u8]) -> Result<Option<Vec<u8>>, AksharaError>;
    async fn put_one_time_prekeys_bytes(&self, device_key: &[u8], prekeys: &[(u32, &[u8])]) -> Result<(), AksharaError>;
    async fn get_one_time_prekeys_bytes(&self, device_key: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, AksharaError>;
    async fn consume_one_time_prekey_bytes(&self, device_key: &[u8], prekey_index: u32) -> Result<Option<Vec<u8>>, AksharaError>;
}
```

### 2.2 High-Level Typed API
These default implementations automatically handle CBOR serialization and partition mapping:
- `put_block(&self, block: &Block)`: Serializes the block to CBOR and calls `put_block_bytes`.
- `get_block(&self, id: &BlockId)`: Retrieves the bytes and deserializes them back into a `Block`.
- `put_prekey_bundle(&self, bundle: &PreKeyBundle)`: Persists the base prekey bundle metadata, serializes individual one-time prekeys, and writes them to the partitioned one-time prekey store.
- `consume_prekey(&self, device_key: &SigningPublicKey, prekey_index: u32)`: Requests atomic byte consumption of a specific one-time prekey, and deserializes the returned bytes into an `EncryptionPublicKey`.

---

## 3. SQLite Storage Adapter (`SqliteStore`)

The `SqliteStore` is implemented at the SDK level (L1) to maintain clean dependency boundaries (L0 does not depend on C/SQLite bindings).

### 3.1 Relational Schema Design
```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Immutable CAS Blocks
CREATE TABLE IF NOT EXISTS blocks (
    block_id BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

-- Immutable CAS Manifests
CREATE TABLE IF NOT EXISTS manifests (
    manifest_id BLOB PRIMARY KEY,
    graph_id BLOB NOT NULL,
    data BLOB NOT NULL
);

-- Active DAG frontiers
CREATE TABLE IF NOT EXISTS graph_heads (
    graph_id BLOB,
    manifest_id BLOB,
    PRIMARY KEY (graph_id, manifest_id)
);

-- Blinded User Lockboxes
CREATE TABLE IF NOT EXISTS lockboxes (
    lakshana BLOB NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lockboxes_lakshana ON lockboxes(lakshana);

-- Base Prekey Bundles (Identity, Signed Prekey, Signature)
CREATE TABLE IF NOT EXISTS prekey_bundles (
    device_key BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

-- One-Time Prekeys (Partitioned for atomic consumption)
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    device_key BLOB NOT NULL,
    prekey_index INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (device_key, prekey_index),
    FOREIGN KEY (device_key) REFERENCES prekey_bundles(device_key) ON DELETE CASCADE
);
```

### 3.2 Concurrency & Performance Enhancements
To scale for multi-user client apps and high-concurrency relays, the following optimizations are implemented:
1. **Prepared Query Caching (`prepare_cached`)**: Compilation of SQL statements is cached per connection. Repeated operations on blocks and manifests reuse compiled statement handles, avoiding SQL re-parsing overhead.
2. **Read Connection Pooling**: A single serialized connection bottleneck prevents parallel queries. `SqliteStore` maintains a thread-safe read pool (`Arc<Mutex<Vec<Connection>>>`). Reads lease dedicated read connections, unlocking parallel execution under SQLite's Write-Ahead Logging (`WAL`) mode.

---

## 4. In-Memory Storage Adapter (`InMemoryStore`)

For testing, `InMemoryStore` implements thread-safe memory maps:
- **Lock Isolation**: Individual read-write locks (`RwLock`) on each map prevent global contention.
- **Partitioned Session Prekeys**: One-time prekeys are partitioned into a nested map (`HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>`).
- **Atomic Deletion**: Key consumption uses a write-lock guard to perform an atomic key removal (`remove(&prekey_index)`), ensuring identical forward-secrecy semantics as the database transactions.

---

## 5. Operational Invariants

### 5.1 Atomic Head Re-indexing
During `put_manifest_bytes`, the database transaction MUST prune parent references and add the new leaf manifest in one atomic operation:
```sql
BEGIN TRANSACTION;
INSERT OR IGNORE INTO manifests (manifest_id, graph_id, data) VALUES (?1, ?2, ?3);
-- For each parent:
DELETE FROM graph_heads WHERE graph_id = ?1 AND manifest_id = ?2;
-- Finally:
INSERT OR IGNORE INTO graph_heads (graph_id, manifest_id) VALUES (?1, ?2);
COMMIT;
```

### 5.2 Atomic Prekey Consumption (Forward Secrecy)
To guarantee session key uniqueness, prekey reads and deletes MUST occur in a serialized transaction:
```sql
BEGIN TRANSACTION;
SELECT data FROM one_time_prekeys WHERE device_key = ?1 AND prekey_index = ?2;
-- If found:
DELETE FROM one_time_prekeys WHERE device_key = ?1 AND prekey_index = ?2;
COMMIT; -- Else rollback
```

---

## 6. Architectural Decision Records (ADR): SQLite Placement & Design

### 6.1 Placement: Why L1 `akshara` and not L0 `aadhaara`?
1. **WebAssembly (WASM) & Pure Rust Portability**:
   - `akshara-aadhaara` (L0) contains core cryptographic models, Merkle-DAG operations, and sync logic. It is designed to be highly portable, targeting platforms like **WebAssembly (WASM)**, native clients, and relays.
   - Including `rusqlite` (which links against the C library of SQLite) in L0 would tie the entire core library to C-linkage, breaking compilation for pure WASM contexts (e.g. standard browsers).
2. **Developer-Facing Cohesion (L1 SDK)**:
   - The `akshara` crate is the L1 Developer SDK. Developers building native applications expect a zero-configuration persistent storage engine right out of the box.
   - Bundling the `SqliteStore` directly inside the `akshara` crate avoids crate proliferation (e.g. creating `akshara-sqlite`), simplifying dependencies.

### 6.2 Placement: Why not a separate crate (e.g., `akshara-sqlite`)?
- **Lean Dependency Graph**: Maintaining separate version cycles, Cargo workspace boundaries, and API publication routes for a single storage driver increases maintenance overhead.
- **SQLite as Default Client Persistence**: SQLite is the primary storage engine for all client applications. Separating it would require developers to explicitly import another crate for basic database features, raising onboarding friction.

### 6.3 Concurrency Considerations: Thread-Safe Pooling
- Standard `Arc<Mutex<Connection>>` models in SQLite serialize all database queries, which causes lock contention and prevents parallel execution of concurrent reads.
- By structuring `SqliteStore` with a dedicated serialized write lock and a pooled set of read-only connections, we unlock SQLite's **Write-Ahead Logging (WAL)** concurrency model—allowing multiple concurrent readers alongside a single active writer without introducing complex external pooling dependencies (like `r2d2`).

---

## 7. References
- [Storage Semantics](semantics.md)
- [Graph Model Specification](../graph-model/README.md)
- [Synchronization Specification](../synchronization/README.md)
