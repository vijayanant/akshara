---
title: "Storage Interface Specification"
subtitle: "The Decoupled GraphStore Trait and API Laws"
version: "0.1.0-alpha.3"
status: "Accepted"
date: "2026-06-04"
---

# Storage Interface Specification

## 1. Motivation

To support decentralized, local-first environments, the Akshara storage layer must satisfy several platform-agnostic constraints:
- **Zero-Knowledge Relays**: Storage nodes and relays must persist and synchronize data without requiring the ability to decrypt or deserialize domain objects (such as blocks or manifests). Payload content must remain opaque.
- **Backend Portability**: Storage backends must be pluggable, supporting flat file systems, embedded key-value engines (e.g. RocksDB), relational databases (e.g. PostgreSQL, SQLite), or browser environments (e.g. IndexedDB, OPFS).
- **Forward Secrecy Envariance**: The key-exchange mechanism (X3DH) requires one-time prekeys to be consumed atomically to prevent session reuse attacks. The storage interface must guarantee atomic read-and-delete behavior.

To achieve this, the primary storage interface—**`GraphStore`**—is defined as a **decoupled, byte-oriented interface**. It separates the "dumb" storage engine (which deals only with raw bytes and indexes) from the "smart" serialization wrapper (which processes cryptographic types and formats).

---

## 2. Interface Definition

Any implementation of the Akshara storage engine MUST expose the following functional domains:

### 2.1 Content-Addressable Storage (CAS)
Manages the retrieval and persistence of immutable, content-addressed blocks and manifests:
- `put_block_bytes(id: BlockId, data: Bytes)`: Persists an immutable data block.
- `get_block_bytes(id: BlockId) -> Option<Bytes>`: Retrieves a data block by its identifier.
- `put_manifest_bytes(id: ManifestId, graph_id: GraphId, parents: List<ManifestId>, data: Bytes)`: Persists a signed manifest and updates the active graph frontier (heads).
- `get_manifest_bytes(id: ManifestId) -> Option<Bytes>`: Retrieves a manifest.

### 2.2 DAG Frontiers (Heads)
Tracks the unmerged leaf nodes (tips) of a graph DAG:
- `get_heads(graph_id: GraphId) -> List<ManifestId>`: Returns the active heads for a specific graph.

### 2.3 Blind Discovery (Lockboxes)
Provides discovery credentials indexed by blinded destination keys (Lakshana):
- `put_lockbox_bytes(lakshana: Bytes, data: Bytes)`: Appends an encrypted invitation credential.
- `get_lockboxes_bytes(lakshana: Bytes) -> List<Bytes>`: Retrieves all credentials matching the Lakshana.

### 2.4 Cryptographic Prekeys (X3DH)
Tracks session initiation parameters and guarantees forward secrecy:
- `put_prekey_bundle_bytes(device_key: Bytes, data: Bytes)`: Stores base prekey bundle details (identity, signed prekey, signatures).
- `get_prekey_bundle_bytes(device_key: Bytes) -> Option<Bytes>`: Retrieves the base prekey bundle.
- `put_one_time_prekeys_bytes(device_key: Bytes, prekeys: List<(Index, Bytes)>)`: Writes a batch of active one-time prekeys.
- `get_one_time_prekeys_bytes(device_key: Bytes) -> List<(Index, Bytes)>`: Retrieves all active one-time prekeys.
- `consume_one_time_prekey_bytes(device_key: Bytes, index: Index) -> Option<Bytes>`: Atomically reads and deletes a single one-time prekey.

---

## 3. Reference Relational Schema (SQL)

For relational storage backends (e.g. PostgreSQL or SQLite), the database schema should map to the following structure:

```sql
-- Opaque CAS blocks
CREATE TABLE blocks (
    block_id BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

-- Opaque CAS manifests
CREATE TABLE manifests (
    manifest_id BLOB PRIMARY KEY,
    graph_id BLOB NOT NULL,
    data BLOB NOT NULL
);

-- Active leaves of the graph DAG
CREATE TABLE graph_heads (
    graph_id BLOB NOT NULL,
    manifest_id BLOB NOT NULL,
    PRIMARY KEY (graph_id, manifest_id)
);

-- Opaque discovery credentials
CREATE TABLE lockboxes (
    lakshana BLOB NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX idx_lockboxes_lakshana ON lockboxes(lakshana);

-- Base device prekey metadata
CREATE TABLE prekey_bundles (
    device_key BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

-- One-time session prekeys
CREATE TABLE one_time_prekeys (
    device_key BLOB NOT NULL,
    prekey_index INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (device_key, prekey_index),
    FOREIGN KEY (device_key) REFERENCES prekey_bundles(device_key) ON DELETE CASCADE
);
```

---

## 4. Operational Invariants & Laws

Every storage implementation MUST satisfy the following laws:

### 4.1 Content Address Integrity
- CAS operations (`put_block_bytes` and `put_manifest_bytes`) are content-addressed. Write operations MUST be idempotent. Storing the same identifier multiple times with identical data MUST return success and keep storage state unchanged.

### 4.2 Atomic Head Pruning
- Manifest insertion and frontier re-indexing MUST occur in a single atomic transaction. When writing manifest $M$ for Graph $G$ with parents $P$:
  1. Manifest bytes $M$ are stored.
  2. All manifest IDs in parents list $P$ are removed from the active `graph_heads` table for Graph $G$.
  3. The manifest ID of $M$ is added to the active `graph_heads` table for Graph $G$.

### 4.3 Atomic Prekey Consumption (Forward Secrecy Law)
- `consume_one_time_prekey_bytes` MUST be an atomic read-and-delete transaction. 
- If multiple concurrent threads or clients request consumption of the same `(device_key, index)`, the database must isolate the transaction. Exactly one request must return `Some(Bytes)` and delete the row; all other concurrent requests must return `None`.

---

## 5. References
- [Storage Semantics](semantics.md)
- [Graph Model Specification](../graph-model/README.md)
- [Synchronization Specification](../synchronization/README.md)
