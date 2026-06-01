# Spec 5: Access Control

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles §7, §11](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Errors](./errors.md), [Sync](./sync.md)

---

## Scope

This spec defines:
- Capability-based grants: `grant_access()` / `accept_grant()`
- Capability tokens — portable, unforgeable, scoped
- Ownership transfer: `transfer_ownership()` / `accept_transfer()`
- Key rotation during transfer
- Revocation semantics
- The lockbox protocol underlying grants

It does **not** cover: the aadhaara-level lockbox construction (see aadhaara `base/crypto.rs`), identity derivation (see aadhaara `identity/`).

---

## 1. Capability-Based Grants

### 1.1 Philosophy

Access in Akshara is not managed by an ACL on a server. It is granted by **capabilities** — signed, scoped tokens that the grantee presents to prove access rights.

A capability says: "The owner of this graph has authorized the bearer to read (or write) data at this path prefix."

### 1.2 `GrantBuilder`

```rust
pub struct GrantBuilder {
    recipient_lakshana: Lakshana,
    permissions: GrantPermissions,
    scope_prefix: String,
}

impl GrantBuilder {
    pub fn new() -> Self;

    pub fn to_recipient(self, lakshana: &str) -> Result<Self, Error>;
    pub fn read_only(self) -> Self;
    pub fn read_write(self) -> Self;
    pub fn scope_prefix(self, prefix: &str) -> Self;

    /// Build the grant. Creates a lockbox and stores it in the graph.
    pub async fn build(self, graph: &Graph) -> Result<Grant, Error>;
}
```

### 1.3 `GrantPermissions`

```rust
pub enum GrantPermissions {
    /// Can read data at the scoped paths.
    ReadOnly,

    /// Can read and write data at the scoped paths.
    /// Writes are signed with the grantee's own shadow identity.
    ReadWrite,
}
```

### 1.4 `Grant`

```rust
pub struct Grant {
    /// The graph this grant applies to.
    graph_id: GraphId,

    /// The recipient's lakshana.
    recipient: Lakshana,

    /// What the recipient can do.
    permissions: GrantPermissions,

    /// Path prefix the grant covers.
    scope_prefix: String,

    /// Unique identifier for this grant (used for revocation).
    grant_id: String,

    /// The signed grant token (serialized and signed by the grantor).
    token: GrantToken,
}
```

### 1.5 `GrantToken`

```rust
pub struct GrantToken(String);

impl GrantToken {
    /// Returns the token as a portable string (e.g., base64-encoded).
    pub fn to_string(&self) -> &str;

    /// Parses a token string. Validates the signature.
    /// Revocation is checked at `accept_grant()` time, not here.
    pub fn from_string(s: &str) -> Result<Self, Error>;
}
```

**Structure of a grant token:**
- Serialized grant data (DAG-CBOR)
- Signature by the graph owner's executive identity (Branch 1)
- Base64-encoded for portability

### 1.6 `Graph::grant_access`

```rust
impl Graph {
    /// Create a capability grant for another party.
    ///
    /// The grant is signed by the graph owner and produces a portable token.
    /// The lockbox is stored in the graph at `.akshara.grants/{grant_id}`.
    pub async fn grant_access(&self, builder: GrantBuilder) -> Result<Grant, Error>;
}
```

**Behavior:**

1. Validates the recipient's lakshana
2. Validates the scope prefix (must be a valid path prefix)
3. Generates a unique `grant_id`
4. Creates a lockbox containing the graph key (or a subtree-specific derived key), encrypted with the recipient's public key
5. Stores the lockbox at `.akshara.grants/{grant_id}`
6. Signs the grant data with the owner's executive identity
7. Returns the `Grant` with the embedded `GrantToken`

**Lockbox construction:**

- The graph key is wrapped in a lockbox (X25519 DH + XChaCha20-Poly1305)
- The lockbox is encrypted for the recipient's handshake public key (Branch 3)
- The lockbox is stored in the graph at `.akshara.grants/{grant_id}`
- The token references the lockbox path so the recipient can find it

### 1.7 `Graph::revoke_access`

```rust
impl Graph {
    /// Revoke a previously granted capability.
    ///
    /// Revocation creates a revocation manifest in the graph.
    /// When the recipient syncs, their SDK sees the revocation and
    /// stops decrypting new data from this grant.
    ///
    /// When to revoke is an application-level decision. The SDK
    /// provides the mechanism; the application decides the timing.
    pub async fn revoke_access(&self, grant_id: &str) -> Result<RevocationReport, Error>;
}
```

**Behavior:**

1. Verifies the grant exists at `.akshara.grants/{grant_id}`
2. Creates a revocation manifest at `.akshara.grants/{grant_id}/revoked`
3. The revocation is signed by the graph owner
4. On next sync, the recipient's SDK sees the revocation and:
   - Removes the lockbox from local storage
   - Marks the grant as revoked (future `load`/`insert` calls return `Error::RevokedGrant`)
5. Returns `RevocationReport`

### 1.8 `RevocationReport`

```rust
pub struct RevocationReport {
    /// The grant that was revoked.
    pub grant_id: String,

    /// Revocation prevents the recipient from receiving new data
    /// after the revocation manifest is synced.
    pub prevents_future_sync: bool,

    /// Revocation removes the lockbox from the recipient's local
    /// storage on next sync, preventing further decryption of new data.
    pub removes_local_key_on_sync: bool,
}
```

**What revocation does NOT do:**

- It does NOT delete data already decrypted and cached on the recipient's device. This is a physical limitation.
- It does NOT rotate the graph key. Existing grantees who cached data before revocation can still read that cached data. Key rotation is a separate operation for a future `revoke_with_rotation()` API.

### 1.9 Future Hard Revocation

The API is designed to accommodate future hard revocation modes without breaking changes:

```rust
// Future API — not yet implemented
impl Graph {
    /// Revoke and rotate the graph key.
    /// All grantees (including non-revoked ones) need new lockboxes.
    /// O(N) where N is the number of blocks.
    pub async fn revoke_with_rotation(&self, grant_id: &str) -> Result<HardRevocationReport, Error>;
}
```

This method does not exist yet. The current `revoke_access()` is soft revocation only.

---

## 2. Grant Acceptance

### 2.1 `Client::accept_grant`

```rust
impl Client {
    /// Accept a capability grant from another party.
    ///
    /// This opens the grantor's graph (or a scoped subtree) for access.
    pub async fn accept_grant(&self, token: &str) -> Result<SharedGraph, Error>;
}
```

**Behavior:**

1. Parses and validates the `GrantToken` (signature check)
2. Checks revocation: if the grant has been revoked, returns `Error::RevokedGrant`
3. Opens the lockbox using the client's handshake key (Branch 3)
4. Extracts the graph key (or subtree key) from the lockbox
5. Opens the graph in the client's storage
6. Returns a `SharedGraph` handle

### 2.2 `SharedGraph`

```rust
pub struct SharedGraph {
    /// The grant this handle was created from.
    grant: Grant,

    /// Handle to the grantor's graph.
    graph: Graph,
}

impl SharedGraph {
    /// Returns the permissions of this grant.
    pub fn permissions(&self) -> &GrantPermissions;

    /// Returns the scope prefix of this grant.
    pub fn scope_prefix(&self) -> &str;

    /// Returns the grant ID (for revocation reference).
    pub fn grant_id(&self) -> &str;

    /// Loads data from the scoped path.
    /// Returns AccessDenied if the path is outside the grant scope.
    pub async fn load<T>(&self, path: &str) -> Result<T, Error>
    where
        T: AksharaDocument;

    /// Writes data at the scoped path.
    /// Returns AccessDenied if the grant is read-only or the path is outside scope.
    pub async fn insert<T>(&self, path: &str, value: &T) -> Result<(), Error>
    where
        T: AksharaDocument;
}
```

**Access control on every operation:**

- `load(path)` checks that `path` starts with `scope_prefix`. If not, returns `Error::AccessDenied`.
- `insert(path)` checks both the prefix AND that `permissions == ReadWrite`. If not, returns `Error::AccessDenied`.
- The graph key from the lockbox is used for all decryption — no separate key derivation.

---

## 3. Ownership Transfer

### 3.1 Philosophy

The initial creator of a graph is the first owner. But ownership can be transferred to another party — permanently. After transfer, the new owner signs all future manifests and the old owner's signing rights are revoked.

### 3.2 `Graph::transfer_ownership`

```rust
impl Graph {
    /// Initiate an ownership transfer to another party.
    ///
    /// This creates a signed transfer token that the recipient can redeem.
    /// The transfer is NOT complete until the recipient accepts it.
    pub async fn transfer_ownership(&self, recipient_lakshana: &str) -> Result<TransferToken, Error>;
}
```

**Behavior:**

1. Validates the recipient's lakshana
2. Creates a transfer manifest with:
   - `from_identity`: current owner's public identity fingerprint
   - `to_identity`: recipient's lakshana
   - `graph_key_encrypted`: graph key wrapped in a lockbox for the recipient
   - `transfer_type`: Fast or WithRotation (determined by the recipient at acceptance)
3. Signs the transfer manifest with the current owner's executive identity
4. Returns a `TransferToken`

### 3.3 `TransferToken`

```rust
pub struct TransferToken {
    /// The graph being transferred.
    graph_id: GraphId,

    /// The lakshana of the new owner.
    new_owner: Lakshana,

    /// The signed token (for verification).
    token: String,
}
```

### 3.4 `Client::accept_transfer`

```rust
impl Client {
    /// Begin accepting a transfer initiated by the current graph owner.
    pub fn accept_transfer(&self, token: &TransferToken) -> TransferAcceptBuilder;
}
```

### 3.5 `TransferAcceptBuilder`

```rust
pub struct TransferAcceptBuilder {
    client: &Client,
    token: TransferToken,
    key_rotation: bool,
}

impl TransferAcceptBuilder {
    /// Re-encrypt all existing blocks with a new graph key derived from
    /// the new owner's identity. This provides a clean break — the old
    /// owner can no longer decrypt historical data.
    ///
    /// O(N) where N is the number of existing blocks.
    pub fn with_key_rotation(self) -> Self;

    /// Execute the transfer.
    pub async fn execute(self) -> Result<Graph, Error>;
}
```

### 3.6 Transfer Execution

**Without key rotation (Fast, O(1)):**

1. Validates the transfer token signature
2. Opens the lockbox to extract the graph key
3. Creates a new manifest signed by the NEW owner's shadow identity
4. The manifest type is `AksharaSuccessionV1` (ownership transfer checkpoint)
5. Revokes the old owner from the identity graph
6. Returns the `Graph` handle

**With key rotation (O(N)):**

1. All steps from Fast transfer, plus:
2. Derives a NEW graph key from the new owner's identity
3. Iterates over ALL existing blocks:
   - Decrypts each block with the old key
   - Re-encrypts with the new key
   - Recomputes the block's CID (content changed → new CID)
4. Rebuilds the entire Merkle Index with new CIDs
5. Creates a new manifest pointing to the rebuilt index
6. All historical data is now encrypted under the new key only

**Progress reporting:**

```rust
impl TransferAcceptBuilder {
    /// Execute the transfer with a progress callback.
    /// Only meaningful when key rotation is enabled.
    pub async fn execute_with_progress<F>(self, on_progress: F) -> Result<Graph, Error>
    where
        F: FnMut(TransferProgress) + Send;
}

pub struct TransferProgress {
    pub blocks_processed: usize,
    pub total_blocks: usize,
    pub percent_complete: f64,
}
```

### 3.7 Transfer Lifecycle States

```
  ┌─────────────────┐
  │  Owned by A     │  ← A signs all manifests
  │  (creator)      │     A holds the graph key
  └────────┬────────┘
           │ A calls transfer_ownership(B)
           │ → TransferToken created
           │    (still owned by A until B accepts)
           ▼
  ┌─────────────────┐
  │  Pending        │  ← A still signs, A still has key
  │  Transfer       │     Token exists but not yet redeemed
  │                 │     A can cancel by continuing to write
  └────────┬────────┘
           │ B calls accept_transfer(token)
           │ → New manifest signed by B
           │ → A's signing rights revoked
           ▼
  ┌─────────────────┐
  │  Owned by B     │  ← B signs all future manifests
  │  (new owner)    │     B holds the graph key
  └─────────────────┘
```

**What happens to A's existing handle after transfer:**

- A's `Graph` handle still works locally — A can still read and write
- But A's writes are no longer the authoritative chain — B's manifests supersede them
- A will see a conflict when syncing (their head vs B's head) — B's head wins because it has the transfer manifest
- A's graph key is still valid for decrypting historical blocks they cached
- If key rotation was used, A's old key becomes useless for new data

---

## 4. Design Decisions

### 4.1 Why grants are capability tokens, not ACL entries

An ACL requires a central authority to check "is this user allowed?" Capabilities are self-contained — the token itself is the proof. This matches Akshara's offline-first model: the grantee doesn't need to contact the grantor to verify access, they just present the token.

### 4.2 Why there is no time-based expiry

Time-based expiry requires a trusted clock. In Akshara there is none — each device has its own wall clock, the relay is blind, and devices operate offline. A recipient can set their clock back and continue decrypting "expired" data. Pretending otherwise gives developers false confidence.

Instead, access is granted until explicitly revoked. The application layer decides *when* to revoke — after a consultation ends, after a project completes, on a schedule. The SDK provides `revoke_access()`; the app decides when to call it.

### 4.3 Why revocation is "soft" for now

Soft revocation (stop sync, remove lockbox) is immediate and cheap. Hard revocation (rotate the graph key, re-encrypt all blocks) is O(N) and expensive. Starting with soft revocation lets us validate the API and protocol before committing to the computational cost of hard revocation. The API is designed so `revoke_with_rotation()` can be added later without breaking changes.

### 4.4 Why ownership transfer has two modes

`transfer_fast` is O(1) but leaves the old owner with historical read access. `transfer_with_rotation` is O(N) but provides a clean cryptographic break. Both are valid — the choice depends on the threat model. A hospital transferring a patient record might choose rotation for HIPAA compliance. A family sharing a recipe graph might choose fast for convenience.

### 4.5 Why the transfer token is signed by the old owner

This prevents unauthorized transfer attempts. Only the current owner can initiate a transfer. The token's signature proves the owner authorized it.

---

## 5. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `GrantBuilder`, `Grant`, `GrantToken` | §1 | [Client & Graph](./client-and-graph.md) |
| `SharedGraph` | §2.2 | [Client & Graph](./client-and-graph.md) |
| `transfer_ownership()` / `accept_transfer()` | §3 | [Client & Graph](./client-and-graph.md) |
| `RevocationReport` | §1.8 | [Errors](./errors.md) |
| Lockbox construction | §1.6 | aadhaara `base/crypto.rs` |

---

**Certified by:**  
*The Akshara Council of One*
