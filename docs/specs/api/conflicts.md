# Spec 6: Conflicts

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles §6](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Errors](./errors.md), [Sync](./sync.md)

---

## Scope

This spec defines:
- Conflict detection — how divergent heads surface to the developer
- `ConflictPolicy` — opt-in conflict notification vs auto-merge
- `branches()` — inspecting concurrent versions
- `resolve_conflict()` — merging branches into a single version
- `set_merge_strategy()` — automated conflict resolution with custom functions

It does **not** cover: the aadhaara-level reconciliation that creates divergent heads — that is the kernel's responsibility.

---

## 1. Conflict Detection

### 1.1 How Conflicts Arise

When two parties write to the same path concurrently (without seeing each other's manifest), the sync protocol creates **divergent heads** — two manifests that are not ancestors of each other. The path resolves to two different blocks.

This is not an error. It is a natural consequence of offline-first, peer-to-peer writes.

### 1.2 `ConflictPolicy`

```rust
pub enum ConflictPolicy {
    /// Auto-merge: last-write-wins based on manifest timestamp.
    /// Conflicts are silently resolved. This is the DEFAULT.
    AutoMerge,

    /// Notify: conflicts are surfaced via the watch stream (see [Reactive](./reactive.md))
    /// and are accessible via `branches()`. The developer decides how to resolve.
    Notify,
}
```

### 1.3 `Graph::set_conflict_policy`

```rust
impl Graph {
    /// Set how conflicts are handled for this graph.
    /// Default: ConflictPolicy::AutoMerge.
    pub fn set_conflict_policy(&self, policy: ConflictPolicy);
}
```

**Behavior:** The policy is stored in-memory on the `Graph` handle. It affects how `sync_scope()` and `flush()` handle divergent heads.

### 1.4 Auto-Merge Behavior

When `ConflictPolicy::AutoMerge` is active:
1. During sync, divergent heads are detected
2. The manifest with the **later timestamp** wins
3. If timestamps are equal, the manifest with the **lexicographically lower CID** wins (deterministic tie-break)
4. The losing head is preserved in the DAG but is not the active head for path resolution
5. The conflict is logged in the `SyncReport.conflicts_detected` count

This ensures **symmetric convergence** — any two SDKs performing the same merge reach the same state without communication.

---

## 2. Inspecting Conflicts

### 2.1 `branches()`

```rust
impl Graph {
    /// Get all concurrent versions of a path.
    ///
    /// Returns multiple branches only when the path has divergent heads
    /// that have not been resolved. If the path has a single head,
    /// returns a single-element vector.
    pub async fn branches<T>(&self, path: &str) -> Result<Vec<DocumentBranch<T>>, Error>
    where
        T: AksharaDocument;
}
```

### 2.2 `DocumentBranch<T>`

```rust
pub struct DocumentBranch<T> {
    /// The deserialized value of this branch.
    pub value: T,

    /// The block ID of this version.
    pub block_id: BlockId,

    /// The manifest that contains this branch's head.
    pub manifest_id: ManifestId,

    /// When this version was authored (from manifest header).
    pub authored_at: DateTime<Utc>,

    /// The fingerprint of the author (obfuscated path hash).
    pub author_fingerprint: String,

    /// Whether this is the currently active (winning) branch.
    pub is_active: bool,
}
```

### 2.3 Example

```rust
let branches: Vec<DocumentBranch<PatientNote>> = graph.branches("notes/consultation-001").await?;

for branch in &branches {
    println!(
        "Version by {} at {}: {}",
        branch.author_fingerprint,
        branch.authored_at,
        branch.is_active.then_some(" (ACTIVE)").unwrap_or("")
    );
    println!("  {}", branch.value.body);
}
```

---

## 3. Resolving Conflicts

### 3.1 Manual Resolution

```rust
impl Graph {
    /// Resolve a conflict by providing the merged value.
    ///
    /// The merged value is inserted at the path, with ALL divergent heads
    /// as parents. This creates a merge commit in the DAG.
    pub async fn resolve_conflict<T>(&self, path: &str, merged: &T) -> Result<(), Error>
    where
        T: AksharaDocument;
}
```

**Behavior:**

1. Identifies all divergent heads at the path
2. Creates a new block for `merged` with all divergent heads as parents
3. Updates the index to point to the new block
4. Flushes the merge (creates a manifest)
5. The merge commit is the new single head — conflict resolved

### 3.2 Automated Merge Strategies

```rust
impl Graph {
    /// Register an automated merge strategy for a specific path.
    ///
    /// When a conflict is detected at this path (or a descendant),
    /// the merge function is called with the local and remote branches.
    /// The function returns the merged value, which is automatically resolved.
    ///
    /// If the merge function returns None, the conflict falls back to
    /// the Notify policy (developer must resolve manually).
    pub fn set_merge_strategy<T, F>(&self, path: &str, merge: F)
    where
        T: AksharaDocument,
        F: Fn(T, T) -> Option<T> + Send + Sync + 'static;
}
```

### 3.3 Built-in Merge Strategies

The SDK provides common merge strategies for standard types:

```rust
pub mod merge_strategies {
    /// Keep the version with the later timestamp.
    pub fn latest<T: AksharaDocument>(local: T, remote: T, local_time: DateTime<Utc>, remote_time: DateTime<Utc>) -> T;

    /// Union of two vectors (deduplicated by Eq).
    pub fn union<T: Eq + Clone>(local: Vec<T>, remote: Vec<T>) -> Vec<T>;

    /// Concatenate two strings with a separator.
    pub fn concat(local: String, remote: String, separator: &str) -> String;
}
```

### 3.4 Example: Custom Merge for Allergies

```rust
// Merge allergies by union (keep all unique allergies)
graph.set_merge_strategy("record/allergies", |local: Vec<Allergy>, remote: Vec<Allergy>| {
    let mut merged = local.clone();
    merged.extend(
        remote.into_iter()
            .filter(|a| !merged.iter().any(|b| b.substance == a.substance))
    );
    Some(merged)
});
```

When a conflict at `record/allergies` is detected:
1. Both branches are loaded and deserialized
2. The merge function is called
3. The result is automatically resolved via `resolve_conflict()`
4. A manifest is signed

If the merge function returns `None`, the conflict falls back to `Notify` policy.

---

## 4. Conflict Flow Detail

```
Two parties write to "record/notes" concurrently.
    │
    ├─ Party A: inserts note_v1, flushes → manifest_A
    ├─ Party B: inserts note_v2, flushes → manifest_B
    │   (B has not seen manifest_A)
    │
    ├─ sync_scope() runs
    │   ├─ Reconciler detects: manifest_A and manifest_B are not ancestors
    │   ├─ Both claim "record/notes" as their content_root child
    │   └─ Conflict detected!
    │
    ├─ If ConflictPolicy::AutoMerge:
    │   ├─ Compare timestamps: manifest_B is later
    │   ├─ manifest_B wins, note_v2 is active
    │   ├─ manifest_A is preserved in DAG but not active
    │   └─ SyncReport.conflicts_detected += 1
    │
    ├─ If ConflictPolicy::Notify + no merge strategy:
    │   ├─ branches("record/notes") returns [Branch(note_v1), Branch(note_v2)]
    │   ├─ watch stream emits GraphEvent::Conflict { path, branches }
    │   └─ Developer calls resolve_conflict("record/notes", &merged)
    │
    └─ If ConflictPolicy::Notify + merge strategy registered:
        ├─ Merge function called with (note_v1, note_v2)
        ├─ Returns Some(merged_note)
        ├─ resolve_conflict() called automatically
        └─ New manifest signed with merged value
```

---

## 5. Design Decisions

### 5.1 Why auto-merge is the default

Most conflicts are benign — two people editing different fields, appending to collections, etc. Auto-merge with deterministic tie-break ensures the system converges without developer intervention. The `Notify` policy is for cases where the developer needs semantic awareness (e.g., two doctors editing the same diagnosis).

### 5.2 Why CID is the tie-break for equal timestamps

Timestamps are from manifest headers, which are set to 0 for the rebirth invariant. When timestamps are equal (which is common for manifests created in the same flush), the lexicographically lower CID provides a deterministic, universally agreed-upon winner. Every SDK on earth reaches the same conclusion.

### 5.3 Why merge strategies return `Option<T>`

Some conflicts cannot be automatically merged (e.g., two people setting a boolean flag to different values). Returning `None` from the merge function delegates to manual resolution — the developer sees the conflict and decides.

### 5.4 Why merge commits have all divergent heads as parents

This preserves the full history. The merge commit is a DAG node with multiple parents, proving that both versions were considered and merged. An auditor can trace the merge back to both source branches.

---

## 6. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `ConflictPolicy` | §1.2 | [Client & Graph](./client-and-graph.md) |
| `branches()` | §2.1 | [Reactive](./reactive.md) |
| `resolve_conflict()` | §3.1 | [Reactive](./reactive.md) |
| `set_merge_strategy()` | §3.2 | [Reactive](./reactive.md) |
| Conflict flow | §4 | [Sync](./sync.md) |

---

**Certified by:**  
*The Akshara Council of One*
