---
title: "Symmetric Reconciliation Specification"
subtitle: "LCA-Based Gap Detection in Merkle-DAGs"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Symmetric Reconciliation Specification

## 1. Motivation

### The Problem

Two peers have different views of the same graph. How do they efficiently identify what each is missing?

```
Peer A has: [A, B, C]    Peer B has: [A, B, D]
            (A is common, B is common)
            (C is only with A, D is only with B)

Question: What does A need? What does B need?
```

Traditional approaches:
- **Request/response:** Client asks, server responds (centralized)
- **Full sync:** Send everything (wasteful)
- **Merkle tree comparison:** Requires same root (doesn't work for forks)

### The Akshara Solution

**Symmetric Reconciliation** — both peers identify gaps in a single pass:

```
1. Exchange heads: A has [C], B has [D]
2. Walk backwards to find known sets
3. Compute symmetric difference:
   - peer_surplus: What peer has that I lack
   - self_surplus: What I have that peer lacks
4. Both peers now know exactly what to send
```

**Key insight:** Reconciliation is **symmetric** — both peers have knowledge to share.

---

## 2. Overview

Reconciliation is the process of identifying the difference between two separate views of a Merkle-DAG. This document defines the algorithm for determining the bi-directional knowledge gap between a local node and a remote peer.

### Key Concepts

| Term | Definition |
|------|------------|
| **Frontier (Heads)** | Set of manifest CIDs with no children |
| **Known Set** | All manifest CIDs reachable by walking backward from heads |
| **Surplus** | CIDs in one peer's known set but not the other's |
| **Delta** | Expanded surplus (includes data blocks, not just manifests) |
| **Comparison** | Result: `peer_surplus` + `self_surplus` |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Reconciliation Flow                                        │
│                                                             │
│  Peer A                          Peer B                     │
│  Heads: [A_head]                 Heads: [B_head]            │
│                                                             │
│       │                             │                       │
│       └────── Exchange Heads ───────┘                       │
│                                                             │
│       │                             │                       │
│  Compute Known Set A         Compute Known Set B            │
│  Walk backward from A_head   Walk backward from B_head      │
│                                                             │
│       │                             │                       │
│  peer_surplus = B - A          peer_surplus = A - B         │
│  self_surplus = A - B          self_surplus = B - A         │
│                                                             │
│       │                             │                       │
│       └────── Exchange Comparison ──┘                       │
│                                                             │
│  Both peers now know what to send                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Definitions

| Term | Formal Definition |
|------|-------------------|
| **Frontier (Heads)** | `Heads = { h ∈ Manifests | ∄ m : h ∈ m.parents }` |
| **Known Set** | `Known(Heads) = { m ∈ Manifests | m reachable from Heads via parent links }` |
| **Surplus** | `Surplus(A, B) = Known(B) - Known(A)` |
| **Delta** | `Delta(Surplus) = Surplus ∪ { b ∈ Blocks | b referenced by m ∈ Surplus }` |

## 4. Sync Modes

Akshara supports two reconciliation modes to balance performance and completeness.

### 4.1. Fast Sync (Shallow Reconciliation)
*   **Purpose:** Rapid state availability for edge devices.
*   **Logic:** The `Reconciler` recursively identifies missing `Manifests` and their immediate `content_root` blocks. It stops the recursive walk at the **Lowest Common Ancestor (LCA)** of the manifests.
*   **Invariant:** Only the latest versions of resources (and any concurrent conflicts) are identified. Historical "atoms" (block parents) older than the LCA are ignored.

### 4.2. Full Sync (Deep Reconciliation)
*   **Purpose:** Archival durability and total history preservation (Relays).
*   **Logic:** The `Reconciler` recursively identifies EVERY `Manifest` and EVERY `Block` parent in the surplus history.
*   **Invariant:** Every atom of the graph is identified, ensuring the entire Resource DAG is preserved.

### 4.3. Conflict Identification
Regardless of the mode, the `Reconciler` MUST identify **concurrent heads** (forks). If multiple manifests share a common ancestor but have no common child, all divergent blocks for a given path MUST be included in the `Delta` to ensure the application layer can surface the conflict to the user.

---

## 5. Reconciliation Algorithm

### 4.1. Main Algorithm

```
Input:  local_heads, remote_heads, store
Output: Comparison { peer_surplus: Delta, self_surplus: Delta }

// Step 1: Validate input
1.1 if len(remote_heads) > MAX_HEADS (1024):
        return error, "Too many heads"

// Step 2: Compute known sets
2.1 local_known = compute_known_set(local_heads, store)
2.2 remote_known = compute_known_set(remote_heads, store)

// Step 3: Compute symmetric difference
3.1 peer_surplus_manifests = remote_known - local_known
3.2 self_surplus_manifests = local_known - remote_known

// Step 4: Expand to deltas (include data blocks)
4.1 peer_surplus = expand_to_delta(peer_surplus_manifests, store)
4.2 self_surplus = expand_to_delta(self_surplus_manifests, store)

// Step 5: Validate delta size
5.1 if len(peer_surplus) > MAX_DELTA (100000):
        return error, "Delta too large"
5.2 if len(self_surplus) > MAX_DELTA (100000):
        return error, "Delta too large"

// Step 6: Return comparison
6.1 return Comparison {
        peer_surplus: peer_surplus,
        self_surplus: self_surplus
    }
```

### 4.2. Known Set Computation (BFS Walk)

```
Input:  heads, store
Output: known_set (set of CIDs)

1. known = {}
2. queue = heads
3. visited = {}

4. while queue is not empty:
       cid = queue.pop()

       if cid in visited:
           continue
       visited.add(cid)

       if cid in known:
           continue

       manifest = store.get_manifest(cid)
       if manifest is null:
           continue  // Missing manifest; skip

       known.add(cid)

       // Add parents to queue
       for parent_cid in manifest.header.parents:
           queue.push(parent_cid)

5. return known
```

### 4.3. Delta Expansion

```
Input:  manifest_cids, store
Output: delta (set of addresses: manifests + blocks)

1. delta = {}
2. manifest_queue = manifest_cids
3. block_queue = {}
4. visited = {}

5. // Collect all manifests
6. while manifest_queue is not empty:
       cid = manifest_queue.pop()

       if cid in visited:
           continue
       visited.add(cid)

       delta.add_manifest(cid)

       manifest = store.get_manifest(cid)
       if manifest is null:
           continue

       // Add content root to block queue
       block_queue.push(manifest.header.content_root)

       // Add parent manifests
       for parent_cid in manifest.header.parents:
           manifest_queue.push(parent_cid)

7. // Collect all blocks (recursive)
8. while block_queue is not empty:
       cid = block_queue.pop()

       if cid in visited:
           continue
       visited.add(cid)

       delta.add_block(cid)

       block = store.get_block(cid)
       if block is null:
           continue

       // Add parent blocks
       for parent_cid in block.parents:
           block_queue.push(parent_cid)

9. return delta
```

---

## 5. Resource Constraints

To prevent Denial-of-Service (DoS) and memory exhaustion, the following limits MUST be enforced:

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| **Head Limit** | 1024 heads max | Prevents memory exhaustion from large frontier |
| **Delta Limit** | 100,000 addresses max | Prevents unbounded expansion |
| **BFS Depth** | Implicit (DAG structure) | No explicit depth limit; DAG is acyclic |

### Error Handling

```
if len(heads) > 1024:
    return Error::TooManyHeads

if len(delta) > 100000:
    return Error::DeltaTooLarge

if manifest not found during walk:
    // Skip missing manifest; continue walk
    // Missing data will be fetched during fulfillment
```

---

## 6. Test Vectors

### Test Vector 1: Simple Linear History

```
Peer A has: Manifest A → Manifest B → Manifest C (head)
Peer B has: Manifest A → Manifest B

Heads:
  A: [C]
  B: [B]

Known Sets:
  A: {A, B, C}
  B: {A, B}

Comparison:
  peer_surplus (B's view of what A lacks): {}  // B has nothing A lacks
  self_surplus (A's view of what B lacks): {C}  // A has C, B lacks it

Result: A sends C to B
```

### Test Vector 2: Concurrent Edits (Fork)

```
Peer A has: Manifest A → Manifest B (head)
Peer B has: Manifest A → Manifest C (head)

Heads:
  A: [B]
  B: [C]

Known Sets:
  A: {A, B}
  B: {A, C}

Comparison:
  peer_surplus (A's view): {C}  // B has C, A lacks it
  self_surplus (A's view): {B}  // A has B, B lacks it

Result: A and B exchange B and C (both have gaps to fill)
```

### Test Vector 3: Already Converged

```
Peer A has: Manifest A → Manifest B (head)
Peer B has: Manifest A → Manifest B (head)

Heads:
  A: [B]
  B: [B]

Known Sets:
  A: {A, B}
  B: {A, B}

Comparison:
  peer_surplus: {}
  self_surplus: {}

Result: No sync needed (already converged)
```

---

## 7. Implementation Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Stateless Execution** | Reconciler logic MUST be deterministic and side-effect free |
| **Asynchronous Processing** | Reconciliation MUST be non-blocking |
| **Idempotent** | Running reconciliation twice with same heads yields same result |
| **Symmetric** | Both peers compute complementary results |

---

## 8. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **DoS via head flooding** | Head limit (1024 max) |
| **Memory exhaustion** | Delta limit (100,000 addresses max) |
| **Malicious DAG structure** | BFS with visited tracking prevents infinite loops |

### Assumptions

1. **Content-addressed integrity:** CIDs are unforgeable
2. **Honest heads:** Peers report accurate head CIDs
3. **DAG structure:** No cycles in the graph

### Limitations

| Limitation | Impact |
|------------|--------|
| **O(N) complexity** | BFS walk scales poorly for large graphs |
| **No partial sync** | Must walk full history; can't sync from timestamp |
| **Missing parent handling** | Missing manifests skipped; may require multiple sync turns |

---

## 9. References

- [Synchronization Overview](README.md)
- [Fulfillment Specification](fulfillment.md)
- [IPFS Bitswap: Block Exchange Protocol](https://github.com/ipfs/specs/blob/main/BITSWAP.md)
