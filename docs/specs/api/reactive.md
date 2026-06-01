# Spec 7: Reactive

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles §9](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Errors](./errors.md), [Conflicts](./conflicts.md), [Sync](./sync.md)

---

## Scope

This spec defines:
- `watch()` — reactive event stream for a graph
- `GraphEvent` — the event type union
- Debouncing and throttling for backpressure
- Event delivery semantics (local vs remote changes)

---

## 1. `watch()`

### 1.1 Signature

```rust
impl Graph {
    /// Create a reactive event stream for changes in this graph.
    ///
    /// The stream emits events for local changes (flushes) and remote
    /// changes (synced from peers).
    ///
    /// The optional `prefix` filters events to only those under the
    /// given path. If `None`, all events are emitted.
    pub async fn watch(&self, prefix: Option<&str>) -> Result<GraphEventStream, Error>;
}
```

### 1.2 `GraphEventStream`

```rust
pub struct GraphEventStream {
    receiver: mpsc::Receiver<GraphEvent>,
    prefix: Option<String>,
}

impl GraphEventStream {
    /// Debounce events: if multiple events arrive within the duration,
    /// only the last one is delivered. Others are dropped.
    pub fn debounce(self, duration: Duration) -> Self;

    /// Throttle events: deliver at most `max_events` per `duration`.
    /// Excess events are coalesced into a single `GraphEvent::ManyChanges`.
    pub fn throttle(self, max_events: usize, duration: Duration) -> Self;
}

impl Stream for GraphEventStream {
    type Item = GraphEvent;
}
```

---

## 2. `GraphEvent`

```rust
pub enum GraphEvent {
    /// A document was written (local flush or remote sync).
    DocumentUpdated {
        path: String,
        block_id: BlockId,
        /// Whether this change originated locally (true) or from a peer (false).
        is_local: bool,
    },

    /// A document was deleted (tombstone created).
    DocumentDeleted {
        path: String,
        is_local: bool,
    },

    /// A collection item was added (push operation).
    CollectionItemAdded {
        collection_path: String,
        item_index: String,  // Fractional index
        block_id: BlockId,
        is_local: bool,
    },

    /// A conflict was detected between divergent heads.
    Conflict {
        path: String,
        /// The number of divergent versions at this path.
        branch_count: usize,
    },

    /// A conflict was automatically resolved by a merge strategy.
    ConflictResolved {
        path: String,
        merged_block_id: BlockId,
        merged_branches: usize,
    },

    /// A flush completed (staged operations sealed into a manifest).
    Flushed {
        manifest_id: ManifestId,
        blocks_created: usize,
        bytes_sealed: u64,
        operations_coalesced: usize,
    },

    /// A sync completed for a scope.
    Synced {
        scope: String,
        report: SyncReport,
    },

    /// Many changes occurred — delivered when throttling coalesces events.
    /// The developer should refresh the affected scope.
    ManyChanges {
        scope: String,
        estimated_count: usize,
    },

    /// An ownership transfer completed.
    OwnershipTransferred {
        from_fingerprint: String,
        to_lakshana: String,
        manifest_id: ManifestId,
    },

    /// An access grant was created.
    GrantCreated {
        grant_id: String,
        recipient_lakshana: String,
        scope_prefix: String,
    },

    /// An access grant was revoked.
    GrantRevoked {
        grant_id: String,
    },
}
```

---

## 3. Event Delivery

### 3.1 Local Events

Local events are emitted when the developer's own operations complete:

| Operation | Events Emitted |
|---|---|
| `insert()` / `push()` / `update()` / `delete()` | None (these are staged, not flushed) |
| `flush()` | `Flushed`, then one `DocumentUpdated` per changed path |
| `resolve_conflict()` | `ConflictResolved`, then `DocumentUpdated` |

### 3.2 Remote Events

Remote events are emitted when `sync_scope()` ingests data from a peer:

| Sync Outcome | Events Emitted |
|---|---|
| New blocks received | `DocumentUpdated` per new block |
| New collection items | `CollectionItemAdded` per item |
| Conflicts detected | `Conflict` (or `ConflictResolved` if auto-merged) |
| Transfer manifest received | `OwnershipTransferred` |
| Grant/revocation blocks | `GrantCreated` / `GrantRevoked` |

### 3.3 Filtering

The `watch(prefix)` argument filters events to only those whose `path` (or `scope`, or `collection_path`) starts with the given prefix.

```
watch(Some("record/"))
// Emits: DocumentUpdated { path: "record/allergies", .. }
// Does NOT emit: DocumentUpdated { path: "meta/title", .. }
```

---

## 4. Backpressure

### 4.1 Debouncing

```rust
let mut events = graph.watch(None).await?.debounce(Duration::from_secs(1));

// If 5 events arrive within 1 second, only the 5th is delivered.
// The previous 4 are dropped.
while let Some(event) = events.next().await {
    // Receives at most 1 event per second
}
```

**When to use:** The UI only needs to refresh once per second regardless of how many changes occurred. Debouncing drops intermediate events.

### 4.2 Throttling

```rust
let mut events = graph.watch(None).await?.throttle(10, Duration::from_secs(5));

// If more than 10 events arrive in 5 seconds, the excess are coalesced
// into a single ManyChanges event.
while let Some(event) = events.next().await {
    match event {
        GraphEvent::ManyChanges { scope, estimated_count } => {
            // Refresh the entire scope
            refresh_scope(&scope);
        }
        other => handle_event(other),
    }
}
```

**When to use:** A large sync pulls in 1000 updates. The app can't process 1000 individual events efficiently. Throttling coalesces them into a `ManyChanges` event with a count.

### 4.3 Combining

Debouncing and throttling can be chained:

```rust
let events = graph.watch(None)
    .await?
    .debounce(Duration::from_millis(500))  // Drop events closer than 500ms
    .throttle(50, Duration::from_secs(5));  // Cap at 50 events per 5s
```

---

## 5. Design Decisions

### 5.1 Why a stream instead of callbacks

Callbacks create ownership confusion (who owns the callback? when is it dropped? what thread does it run on?). A `Stream` is idiomatic Rust — the developer controls consumption with `next()`, `for_each()`, or async iteration. The stream can be combined, filtered, and mapped using standard stream combinators.

### 5.2 Why both debounce and throttle

Debouncing drops all but the last event in a window — good for "I only care about the final state." Throttling caps the rate but preserves individual events up to the cap — good for "I want to see changes but not get overwhelmed." They serve different use cases and are composable.

### 5.3 Why `ManyChanges` exists

Without a coalesced event, a large sync would either flood the stream (1000+ events) or require the SDK to silently drop events (data loss). `ManyChanges` is honest: it tells the developer "a lot changed, you should refresh the scope" without pretending to deliver every individual event.

### 5.4 Why `is_local` is included

The developer may want to distinguish between their own changes and changes from peers. For example, a "typing indicator" or "someone else edited this" badge. The `is_local` field enables this without requiring a separate watch for local vs remote.

---

## 6. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `watch()` | §1.1 | [Client & Graph](./client-and-graph.md) |
| `GraphEvent` | §2 | [Conflicts](./conflicts.md), [Audit](./audit.md) |
| Debouncing / Throttling | §4 | All implementations |
| `ManyChanges` | §2 | — |

---

**Certified by:**  
*The Akshara Council of One*
