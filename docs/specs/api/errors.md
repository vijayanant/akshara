# Spec 3: Errors

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Typed Documents](./typed-documents.md), [Sync](./sync.md), [Access Control](./access-control.md), [Conflicts](./conflicts.md), [Reactive](./reactive.md), [Audit](./audit.md)

---

## Scope

This spec defines the complete `Error` enum for the `akshara` crate. Every error variant, its fields, and the conditions under which it is returned.

---

## 1. The `Error` Enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // === Identity & Vault (category: IDENTITY) ===
    #[error("vault initialization failed: {0}")]
    VaultInit(String),

    #[error("invalid mnemonic: {reason}")]
    InvalidMnemonic { reason: String },

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    // === Storage (category: STORAGE) ===
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    // === Graph Operations (category: GRAPH) ===
    #[error("graph not found: {0}")]
    GraphNotFound(GraphId),

    #[error("invalid lakshana: {0}")]
    InvalidLakshana(String),

    #[error("nothing to flush — staging is empty")]
    NothingToFlush,

    #[error("invalid path: {path} — {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("path not found: {0}")]
    PathNotFound(String),

    // === Serialization (category: SERDE) ===
    #[error("serialization failed: {0}")]
    Serialization(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("deserialization failed: {path}: {reason}")]
    Deserialization { path: String, reason: String },

    // === Crypto (category: CRYPTO) ===
    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("block size exceeded: path={path}, size={size}, max={max}")]
    BlockSizeExceeded { path: String, size: usize, max: usize },

    // === Sync (category: SYNC) ===
    #[error("sync failed: {0}")]
    SyncFailed(String),

    #[error("sync transport error: {0}")]
    SyncTransport(String),

    // === Access Control (category: ACCESS) ===
    #[error("access denied: {resource} — {reason}")]
    AccessDenied { resource: String, reason: String },

    #[error("revoked grant: {0}")]
    RevokedGrant(String),

    #[error("transfer failed: {0}")]
    TransferFailed(String),

    // === Conflicts (category: CONFLICT) ===
    #[error("conflict detected at path: {0}")]
    Conflict(String),

    #[error("conflict resolution failed: {0}")]
    ConflictResolution(String),

    // === Audit (category: AUDIT) ===
    #[error("authority verification failed: {0}")]
    AuthorityVerificationFailed(String),

    #[error("provenance incomplete: {0}")]
    ProvenanceIncomplete(String),

    // === Internal (category: INTERNAL) ===
    #[error("internal error: {0}")]
    Internal(String),
}
```

---

## 2. Error Categories

### 2.1 Identity & Vault

| Variant | When returned |
|---|---|
| `VaultInit` | `Client::init()` fails to create the vault backend (keychain unavailable, disk full) |
| `InvalidMnemonic` | The provided mnemonic is not a valid BIP-39 phrase (wrong word count, invalid words, bad checksum) |
| `Vault` | An operation on the vault fails during a cryptographic operation (key unavailable, signing fails) |
| `Identity` | Identity derivation fails (bad seed, invalid BIP-32 path) |

### 2.2 Storage

| Variant | When returned |
|---|---|
| `Storage` | The storage backend fails to read/write a block, manifest, or staging operation. Wraps aadhaara's `StorageError`. |

### 2.3 Graph Operations

| Variant | When returned |
|---|---|
| `GraphNotFound` | `open_graph()` is called with a Lakshana that resolves to a `GraphId` with no local heads |
| `InvalidLakshana` | The lakshana string fails parsing (invalid encoding, wrong length) |
| `NothingToFlush` | `flush()` is called when the staging buffer is empty |
| `InvalidPath` | A path fails validation: doesn't start with `/`, contains null bytes, exceeds 1024 chars, uses reserved `.akshara.*` segment |
| `PathNotFound` | `load()` or `exists()` is called with a path that doesn't exist in the current manifest, or has been tombstoned |

### 2.4 Serialization

| Variant | When returned |
|---|---|
| `Serialization` | A value cannot be serialized to DAG-CBOR during `insert()`, `push()`, or `update()` |
| `Deserialization` | Bytes at a path cannot be deserialized into the target type. The `path` field identifies where the failure occurred. |

### 2.5 Crypto

| Variant | When returned |
|---|---|
| `Decryption` | A block cannot be decrypted with the current graph key (wrong key, corrupted ciphertext, nonce mismatch) |
| `SignatureVerification` | A block's Ed25519 signature fails verification (tampered data, wrong author key) |
| `BlockSizeExceeded` | A non-`#[chunked]` field's serialized size exceeds `max_block_size`. The error includes the path, actual size, and limit. |

### 2.6 Sync

| Variant | When returned |
|---|---|
| `SyncFailed` | A sync operation fails at the protocol level (reconciliation error, convergence failure) |
| `SyncTransport` | The transport layer fails (connection lost, timeout, peer unreachable) |

### 2.7 Access Control

| Variant | When returned |
|---|---|
| `AccessDenied` | The current identity does not have the capability to access the requested path. The `reason` field explains why (e.g., "no grant for this scope", "grant revoked", "path outside grant scope"). |
| `RevokedGrant` | A grant was explicitly revoked by the graph owner. The parameter is the grant ID. |
| `TransferFailed` | An ownership transfer failed (invalid token, wrong initiator, already transferred) |

### 2.8 Conflicts

| Variant | When returned |
|---|---|
| `Conflict` | Concurrent writes to the same path created divergent heads, and no merge strategy is configured |
| `ConflictResolution` | A `resolve_conflict()` call failed (e.g., the resolution itself creates an invalid state) |

### 2.9 Audit

| Variant | When returned |
|---|---|
| `AuthorityVerificationFailed` | A manifest's authority chain cannot be verified (signer not in identity graph, signer revoked, anchor mismatch) |
| `ProvenanceIncomplete` | A `prove()` call cannot construct the full provenance chain (missing intermediate blocks, broken manifest chain) |

### 2.10 Internal

| Variant | When returned |
|---|---|
| `Internal` | An unexpected invariant violation that the developer cannot recover from. This should never occur in normal operation. If it does, it is a bug in the SDK. |

---

## 3. Error Design Principles

### 3.1 No `unwrap()` on security-sensitive paths

Any operation involving cryptography, path resolution, or manifest verification must return a descriptive `Error` — never panic. The only exceptions are internal test code.

### 3.2 Every error is actionable

The developer should be able to distinguish between:
- "This path doesn't exist" (`PathNotFound`) vs "You can't access this path" (`AccessDenied`)
- "The key is wrong" (`Decryption`) vs "The signature is invalid" (`SignatureVerification`)
- "The data is too big, use #[chunked]" (`BlockSizeExceeded`) vs "The data can't be serialized" (`Serialization`)

### 3.3 Errors include context

Where relevant, errors include the path, size, identity, or timestamp that caused the failure. This enables the developer to log and debug without reconstructing state.

### 3.4 `Internal` errors are bugs

If a developer encounters `Error::Internal`, it is a defect in the SDK. The error message should include enough information to file a useful bug report.

---

## 4. Error Mapping by Operation

| Operation | Possible Errors |
|---|---|
| `Client::init()` | `VaultInit`, `InvalidMnemonic`, `Vault`, `Identity`, `Storage` |
| `Client::create_graph()` | `Vault`, `Identity`, `Storage` |
| `Client::open_graph()` | `InvalidLakshana`, `GraphNotFound` |
| `Client::list_graphs()` | `Storage` |
| `Client::forget_graph()` | `Storage` |
| `Graph::flush()` | `NothingToFlush`, `Serialization`, `BlockSizeExceeded`, `Decryption`, `Vault`, `Storage`, `Identity`, `Internal` |
| `Graph::insert()` | `InvalidPath`, `Serialization`, `Storage` |
| `Graph::push()` | `InvalidPath`, `Serialization`, `Storage` |
| `Graph::update()` | `InvalidPath`, `Serialization`, `Storage` |
| `Graph::delete()` | `InvalidPath`, `Storage` |
| `Graph::load()` | `PathNotFound`, `Decryption`, `SignatureVerification`, `Deserialization`, `Storage` |
| `Graph::exists()` | `Storage`, `PathNotFound` (for malformed paths) |
| `Graph::list()` | `Storage`, `PathNotFound` (for malformed prefixes) |
| `Graph::history()` | `PathNotFound`, `Decryption`, `SignatureVerification`, `Deserialization`, `Storage` |
| `Graph::fetch_blob()` | `PathNotFound`, `Decryption`, `SignatureVerification`, `Storage` |
| `GraphRef::resolve()` | `GraphNotFound`, `AccessDenied`, `PathNotFound`, `Decryption`, `Deserialization`, `Storage` |
| `Graph::sync_scope()` | `SyncFailed`, `SyncTransport`, `Storage` |
| `Graph::grant_access()` | `InvalidPath`, `Vault`, `Storage` |
| `Client::accept_grant()` | `InvalidLakshana`, `RevokedGrant`, `Vault`, `Storage` |
| `Graph::transfer_ownership()` | `InvalidLakshana`, `Vault`, `Storage`, `TransferFailed` |
| `Graph::accept_transfer()` | `TransferFailed`, `Vault`, `Storage` |
| `Graph::revoke_access()` | `AccessDenied`, `Storage` |
| `Graph::branches()` | `Conflict`, `PathNotFound`, `Storage` |
| `Graph::resolve_conflict()` | `ConflictResolution`, `PathNotFound`, `Serialization`, `Storage` |
| `Graph::watch()` | `Internal` (stream creation should not fail) |
| `Graph::prove()` | `PathNotFound`, `ProvenanceIncomplete`, `Storage` |
| `Graph::audit()` | `AuthorityVerificationFailed`, `Storage` |

---

## 5. Design Decisions

### 5.1 Why no `Box<dyn Error>`

Each variant is specific and typed. `Box<dyn Error>` forces the developer to downcast and match on error types. The `akshara::Error` enum is exhaustive — `match` on it is a compile-time guarantee that all error cases are handled.

### 5.2 Why `Internal` exists

Some invariants should be impossible to violate (e.g., "the staging store is available after `Client::init`"). If they are violated due to a race condition or memory corruption, the SDK must surface it. `Internal` is the escape hatch — but it should never be encountered by a developer in normal use.

### 5.3 Why `BlockSizeExceeded` is a separate variant

It is a common developer mistake (forgetting `#[chunked]`). A dedicated variant with `path`, `size`, and `max` fields enables a helpful error message that points to the fix.

---

## 6. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `enum Error` (all variants) | §1 | All specs |
| Error mapping by operation | §4 | All specs |
| `Internal` error semantics | §3.4 | [Client & Graph](./client-and-graph.md) |
| `BlockSizeExceeded` | §2.5 | [Typed Documents](./typed-documents.md) |
| `AccessDenied`, `RevokedGrant` | §2.7 | [Access Control](./access-control.md) |
| `Conflict`, `ConflictResolution` | §2.8 | [Conflicts](./conflicts.md) |

---

**Certified by:**  
*The Akshara Council of One*
