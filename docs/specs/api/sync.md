# Spec 4: Sync

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles §2](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Typed Documents](./typed-documents.md), [Errors](./errors.md)

---

## Scope

This spec defines:
- `sync_scope()` — subtree-scoped synchronization
- `SyncTransport` trait — abstract transport for head exchange and portion streaming
- `SyncReport` — sync operation results
- Lazy path exclusions from sync
- The sync flow at the SDK level

It does **not** cover: the aadhaara-level reconciliation protocol (`Reconciler`, `Delta`, `Portion`) — that is the kernel's responsibility (see aadhaara `protocol/`).

---

## 1. `sync_scope()`

### 1.1 Signature

```rust
impl Graph {
    /// Synchronize a subtree of this graph with the remote peer.
    ///
    /// Only blocks reachable from the given path prefix are fetched.
    /// Lazy fields are excluded by default (see §3).
    pub async fn sync_scope(&self, scope: &str) -> Result<SyncReport, Error>;
}
```

### 1.2 Behavior

1. Gets local heads for this graph from storage
2. Contacts the remote peer via `SyncTransport` to exchange heads
3. Runs the aadhaara reconciliation protocol (`Reconciler::reconcile()`)
4. Filters the resulting `Delta` to only include addresses under `scope`
5. Requests the filtered portions from the remote via `SyncTransport`
6. For each portion:
   - Blindly verifies the CID (recomputes hash from portion data)
   - Audits manifest authority (signer is in identity graph and unrevoked)
   - Ingests into the local store
7. If the identity graph has new manifests, updates the vault's `latest_identity_anchor`
8. Returns `SyncReport`

### 1.3 Scope Semantics

The `scope` parameter is a path prefix. Only blocks whose resolved path starts with `scope` (or is a descendant of `scope`) are fetched.

```
sync_scope("meetings/001/meta")
// Fetches: meetings/001/meta/title, meetings/001/meta/objective
// Does NOT fetch: meetings/001/agenda, meetings/001/attachments

sync_scope("")  // Empty scope = sync entire graph
// Fetches: everything
```

### 1.4 `SyncReport`

```rust
pub struct SyncReport {
    /// Number of manifests received and ingested.
    pub manifests_received: usize,

    /// Number of blocks received and ingested.
    pub blocks_received: usize,

    /// Total bytes transferred (ciphertext over the wire).
    pub bytes_transferred: u64,

    /// Number of conflicts detected (divergent heads at the same path).
    pub conflicts_detected: usize,

    /// Paths that were excluded from sync due to lazy annotations.
    pub lazy_paths_excluded: Vec<String>,
}
```

---

## 2. `SyncTransport` Trait

### 2.1 Definition

```rust
#[async_trait]
pub trait SyncTransport: Send + Sync {
    /// Exchange heads with the remote peer.
    /// Returns (local_heads, remote_heads) for the given graph.
    async fn exchange_heads(
        &self,
        graph_id: GraphId,
        local_heads: Vec<ManifestId>,
    ) -> Result<Vec<ManifestId>, Error>;

    /// Request a set of portions from the remote peer.
    /// Returns a stream of portions in reverse topological order
    /// (manifests before the blocks they reference).
    fn request_portions(
        &self,
        graph_id: GraphId,
        addresses: Vec<Address>,
    ) -> impl Stream<Item = Result<Portion, Error>> + Send;
}
```

### 2.2 Mock Transport (for testing)

```rust
pub struct MockTransport { /* pre-loaded with blocks/manifests */ }

impl MockTransport {
    /// Create a mock transport populated with the given blocks and manifests.
    pub fn new(blocks: Vec<Block>, manifests: Vec<Manifest>) -> Self;
}
```

The mock transport returns pre-loaded data without network I/O. Used in tests and demos.

### 2.3 Real Transport (v0.2)

The gRPC-based transport (tonic) will implement `SyncTransport`. It is not in scope for this spec.

---

## 3. Lazy Path Exclusions

### 3.1 Automatic Exclusion

When `sync_scope()` is called, the SDK automatically excludes lazy paths that are descendants of the scope.

```
sync_scope("record")
// Lazy fields at "record/imaging" and "record/lab_reports" are excluded
// Only non-lazy paths under "record" are fetched
```

### 3.2 How Exclusions Work

1. The SDK loads the schema metadata block (`.akshara.schema`) for the document at the scope root
2. Collects all `#[lazy]` field paths from the schema
3. Filters the reconciliation delta to exclude addresses under lazy paths
4. The `SyncReport` includes `lazy_paths_excluded` so the developer can log what was skipped

### 3.3 Override: Force Include Lazy Paths

```rust
impl Graph {
    /// Synchronize a subtree, including lazy paths.
    pub async fn sync_scope_full(&self, scope: &str) -> Result<SyncReport, Error>;
}
```

`sync_scope_full()` is identical to `sync_scope()` but does NOT apply lazy exclusions. Use this when the developer explicitly wants all data (e.g., on good WiFi before going offline).

---

## 4. Client-Level Sync

### 4.1 `Client::sync`

```rust
impl Client {
    /// Synchronize all graphs with their default scopes.
    ///
    /// Each graph is synced to its root scope ("").
    /// Lazy exclusions apply per-graph.
    pub async fn sync(&self) -> Result<ClientSyncReport, Error>;
}
```

### 4.2 `ClientSyncReport`

```rust
pub struct ClientSyncReport {
    pub graphs_synced: usize,
    pub per_graph: Vec<(GraphId, SyncReport)>,
    pub total_bytes_transferred: u64,
    pub total_conflicts: usize,
}
```

---

## 5. Sync Flow Detail

```
Developer calls: graph.sync_scope("record/consultations")
    │
    ├─ 1. Get local heads from store
    │     heads = [manifest_abc, manifest_def]
    │
    ├─ 2. transport.exchange_heads(graph_id, heads)
    │     → remote_heads = [manifest_ghi, manifest_jkl]
    │
    ├─ 3. Reconciler::reconcile(local_heads, remote_heads)
    │     → Delta { missing_manifests: [manifest_ghi],
    │               missing_blocks: [addr_1, addr_2, addr_3] }
    │
    ├─ 4. Filter delta by scope "record/consultations"
    │     → Filtered: missing_blocks = [addr_2]  (addr_1, addr_3 are outside scope)
    │
    ├─ 5. Exclude lazy paths (if any under scope)
    │     → No lazy paths under consultations
    │
    ├─ 6. transport.request_portions(graph_id, [addr_2])
    │     → Stream<Portion> in reverse topo order
    │
    ├─ 7. For each Portion:
    │     a. Recalculate CID from portion data → verify match
    │     b. Auditor::verify_manifest_authority() → pass
    │     c. store.put_block() / store.put_manifest()
    │
    ├─ 8. Check if identity graph manifest received
    │     → If yes, vault.update_identity_anchor(new_manifest_id)
    │
    └─ 9. Return SyncReport {
              manifests_received: 1,
              blocks_received: 1,
              bytes_transferred: 2048,
              conflicts_detected: 0,
              lazy_paths_excluded: [],
          }
```

---

## 6. Design Decisions

### 6.1 Why `sync_scope` instead of `sync`

The original API had `graph.sync()` which syncs the entire graph. For a healthcare platform with 10,000 patient records, this is unusable on mobile. Scope-based sync is the default because it matches how developers actually use data — they need specific subtrees, not everything.

### 6.2 Why lazy exclusions are automatic

If the developer had to manually exclude lazy paths, they'd need to track which fields are lazy in their own code. The SDK already knows this from the schema metadata. Making it automatic prevents data-transfer mistakes.

### 6.3 Why `SyncTransport` is a trait

The sync protocol is independent of the transport mechanism. Today it's a mock, tomorrow it's gRPC, and someday it might be BLE, WebRTC, or a custom protocol. The SDK only needs `exchange_heads` and `request_portions`.

### 6.4 Why blind verification before ingest

The remote peer (relay or another device) is untrusted. A malicious peer could send a portion with a fabricated CID that points to attacker-controlled content. By recomputing the CID from the portion data before ingest, the SDK ensures the content matches its claimed identity.

---

## 7. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `sync_scope()` | §1 | [Client & Graph](./client-and-graph.md) |
| `SyncTransport` trait | §2 | All implementations |
| Lazy path exclusions | §3 | [Typed Documents](./typed-documents.md) |
| `SyncReport` | §1.4 | [Reactive](./reactive.md) |
| Blind verification | §5 step 7a | [Audit](./audit.md) |

---

**Certified by:**  
*The Akshara Council of One*
