---
title: "Storage Interface Specification"
subtitle: "The GraphStore Trait and Atomic API Laws"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Storage Interface Specification

## 1. Motivation

### The Problem

The core logic needs to store and retrieve blocks/manifests. But:

- **Different backends:** Memory (testing), SQLite (mobile), Relay (server), IPFS (distributed)
- **Async required:** Non-blocking for high concurrency
- **Content-addressed:** Look up by CID, not path
- **Head tracking:** Track manifest frontiers per graph

How do we support all backends without changing core logic?

### The Akshara Solution

**`GraphStore` trait** — a unified interface:

```rust
trait GraphStore: Send + Sync {
    // Data operations
    async fn put_block(&mut self, block: &Block) -> Result<()>;
    async fn get_block(&self, id: &BlockId) -> Result<Option<Block>>;

    // Manifest operations
    async fn put_manifest(&mut self, manifest: &Manifest) -> Result<()>;
    async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>>;
    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>>;

    // Discovery operations
    async fn put_lockbox(&mut self, recipient: &PubKey, lockbox: &Lockbox) -> Result<()>;
    async fn get_lockboxes(&self, recipient: &PubKey) -> Result<Vec<Lockbox>>;
}
```

**Implementations:**
- `InMemoryStore` — Testing, caching
- `SqliteStore` — Mobile, desktop persistence
- `RelayStore` — Server-side storage
- `IPFSStore` — Distributed storage

**Key properties:**
- **Pluggable:** Swap backends without changing core
- **Content-addressed:** All lookups by CID
- **Atomic:** Head updates are atomic
- **Thread-safe:** Send + Sync for concurrency

---

## 2. Overview

This document defines the **`GraphStore`** trait, which serves as the primary interface between the Akshara logic and the physical storage medium. All implementations MUST adhere to these non-blocking, asynchronous standards.

### Key Concepts

| Term | Meaning |
|------|---------|
| **GraphStore** | Trait for content-addressed storage |
| **Heads** | Manifest CIDs with no children (frontier) |
| **Port** | Storage backend implementation |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Akshara Core                                               │
│  (Pure logic, no I/O)                                       │
│                                                             │
│  fn sync(graph_id, store: &impl GraphStore) {               │
│      let heads = store.get_heads(graph_id)?;                │
│      let manifest = store.get_manifest(&heads[0])?;         │
│      // ...                                                 │
│  }                                                          │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ GraphStore trait
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Storage Implementations                                    │
│                                                             │
│  InMemoryStore  SqliteStore  RelayStore  IPFSStore         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Core API

The interface is divided into functional domains for data, metadata, and discovery.

### 3.1. Data Block Operations

#### `put_block`

```rust
async fn put_block(&mut self, block: &Block) -> Result<()>;
```

**Purpose:** Persists an encrypted data unit.

**Invariants:**
- MUST verify CID matches content hash
- MUST be idempotent (same CID = no-op)

**Errors:**
- `IntegrityError` — CID doesn't match content
- `IOError` — Storage failure

---

#### `get_block`

```rust
async fn get_block(&self, id: &BlockId) -> Result<Option<Block>>;
```

**Purpose:** Retrieves a block by its identifier.

**Returns:**
- `Some(Block)` — Block found
- `None` — Block not found

---

### 3.2. Graph Snapshot Operations

#### `put_manifest`

```rust
async fn put_manifest(&mut self, manifest: &Manifest) -> Result<()>;
```

**Purpose:** Persists a signed graph snapshot and updates the "Heads" registry.

**Invariants:**
- MUST verify CID matches content hash
- MUST atomically update heads (add new, remove parents)
- MUST be idempotent

**Algorithm:**
```
1. Verify CID matches manifest header hash
2. Store manifest data
3. For each parent in manifest.header.parents:
       heads.remove(parent)
4. heads.add(manifest.cid)
```

---

#### `get_manifest`

```rust
async fn get_manifest(&self, id: &ManifestId) -> Result<Option<Manifest>>;
```

**Purpose:** Retrieves a manifest by its identifier.

**Returns:**
- `Some(Manifest)` — Manifest found
- `None` — Manifest not found

---

#### `get_heads`

```rust
async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>>;
```

**Purpose:** Returns the current frontier (unmerged manifests) for a specific graph.

**Returns:**
- List of manifest CIDs with no children

---

### 3.3. Discovery Operations

#### `put_lockbox`

```rust
async fn put_lockbox(&mut self, recipient: &PubKey, lockbox: &Lockbox) -> Result<()>;
```

**Purpose:** Stores a discovery credential for a specific public key.

**Invariants:**
- MUST be indexed by recipient's public key
- MUST support multiple lockboxes per recipient

---

#### `get_lockboxes`

```rust
async fn get_lockboxes(&self, recipient: &PubKey) -> Result<Vec<Lockbox>>;
```

**Purpose:** Retrieves all pending invitations for a specific public key.

**Returns:**
- List of lockboxes addressed to recipient

---

## 4. Operational Invariants

Every `GraphStore` implementation MUST guarantee:

| Invariant | Requirement |
|-----------|-------------|
| **Representational Integrity** | MUST verify CID matches payload hash on `put` |
| **Idempotency** | Same CID multiple times MUST be no-op |
| **Atomic Head Pruning** | MUST atomically update heads on manifest store |
| **Thread Safety** | MUST implement `Send + Sync` |

### 4.1. CID Verification

```rust
// On put_block:
let computed_cid = CID(0x57, SHA2-256(DAG-CBOR(block)));
if computed_cid != expected_cid {
    return Err(IntegrityError::CidMismatch);
}
```

### 4.2. Atomic Head Update

```rust
// On put_manifest:
let tx = store.begin_transaction()?;
tx.store_manifest(manifest)?;
for parent in &manifest.header.parents {
    tx.remove_head(graph_id, parent)?;
}
tx.add_head(graph_id, manifest.cid)?;
tx.commit()?;  // All or nothing
```

---

## 5. Error Semantics

Implementations MUST return context-rich errors:

| Error | When Returned |
|-------|---------------|
| **`NotFound`** | Requested CID doesn't exist |
| **`IntegrityError`** | CID doesn't match content hash |
| **`Conflict`** | Atomic update violates constraint |
| **`IOError`** | Physical failure (disk full, timeout) |
| **`InvalidArgument`** | Malformed CID or data |

### Error Example

```rust
match store.get_block(&cid).await {
    Ok(Some(block)) => Ok(block),
    Ok(None) => Err(StorageError::NotFound(cid)),
    Err(e) => Err(StorageError::IOError(e)),
}
```

---

## 6. Test Vectors

### Test Vector 1: Put/Get Block

```
Input:
  block: Block { content: "Hello", type: "data", parents: [], ... }

Process:
  1. store.put_block(&block)
  2. retrieved = store.get_block(&block.cid)

Expected:
  retrieved == Some(block)
```

### Test Vector 2: Idempotent Put

```
Process:
  1. store.put_block(&block)  // First time
  2. store.put_block(&block)  // Second time (same CID)

Expected:
  Both calls return Ok(())
  Storage size unchanged (no duplicate)
```

### Test Vector 3: Atomic Head Update

```
Setup:
  Heads: [A, B]

Process:
  store.put_manifest(Manifest C, parents: [A])

Expected:
  Heads: [B, C]  // A removed, C added
```

---

## 7. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Data corruption** | CID verification on put |
| **Head tampering** | Atomic updates |
| **DoS via storage** | Quotas, limits per graph |

### Assumptions

1. **Storage durability:** Backend persists data reliably
2. **CID integrity:** Storage doesn't modify content
3. **Head security:** Heads registry protected from tampering

### Implementation Notes

1. **Encryption:** Store encrypted content; don't decrypt in storage layer
2. **Caching:** Implement LRU cache for hot CIDs
3. **Batching:** Support batch operations for efficiency

---

## 8. References

- [Storage Overview](README.md)
- [Graph Model Specification](../graph-model/README.md)
- [Synchronization Specification](../synchronization/README.md)
