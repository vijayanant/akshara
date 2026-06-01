# Akshara SDK — API Specifications

**Status:** Draft — For Review  
**Date:** 2026-04-10  
**Derived from:** [API Design Principles](../blueprint/sdk/api-design-principles.md), [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md)

---

## Organization

Each spec is self-contained and cross-references the others. No single document covers everything — pick the spec relevant to your work.

| # | Spec | Topic | Key Types |
|---|------|-------|-----------|
| **1** | [client-and-graph.md](./client-and-graph.md) | Client, Graph, Vault, flush, staging | `Client`, `Graph`, `Vault`, `FlushReport` |
| **2** | [typed-documents.md](./typed-documents.md) | AksharaDocument derive, block modes, lazy fields | `AksharaDocument`, `LazyField<T>`, `DocumentSchema` |
| **3** | [errors.md](./errors.md) | Complete error taxonomy | `enum Error` (all variants) |
| **4** | [sync.md](./sync.md) | Selective sync, transport trait | `sync_scope()`, `SyncTransport`, `SyncReport` |
| **5** | [access-control.md](./access-control.md) | Grants, capabilities, ownership transfer | `GrantBuilder`, `SharedGraph`, `TransferAcceptBuilder` |
| **6** | [conflicts.md](./conflicts.md) | Conflict detection, merge strategies | `ConflictPolicy`, `DocumentBranch<T>`, `set_merge_strategy()` |
| **7** | [reactive.md](./reactive.md) | Event streams, debouncing | `watch()`, `GraphEvent`, `GraphEventStream` |
| **8** | [audit.md](./audit.md) | Provenance, compliance reports | `DocumentProof`, `GraphAuditReport` |
| **9** | [change-tracking.md](./change-tracking.md) | Collaborative change tracking, diffing, signing | `DocField<T>`, `CollaborativeText`, `DocumentDiff` |

---

## Reading Order

For a **new developer** learning the API:
1. [Client & Graph](./client-and-graph.md) — the entry point and main interface
2. [Typed Documents](./typed-documents.md) — how data maps to blocks
3. [Errors](./errors.md) — what can go wrong

For **implementing** a feature:
1. Read the relevant spec
2. Check its cross-reference index for dependent types from other specs
3. Read the [Errors](./errors.md) spec for all variants you might return

For **reviewing** the design:
1. [API Design Principles](../blueprint/sdk/api-design-principles.md) — the 11 principles
2. [Developer Walkthrough](../blueprint/sdk/developer-walkthrough.md) — real-world exercise
3. Then read the individual specs

---

## Relationship to aadhaara

These specs define the **L1 SDK layer** (`akshara` crate). They call into the **L0 kernel** (`akshara-aadhaara` crate) for:

- Block creation, encryption, signing → aadhaara `graph/block.rs`
- Manifest creation → aadhaara `graph/manifest.rs`
- Merkle Index building → aadhaara `traversal/index_builder.rs`
- Graph walking, path resolution → aadhaara `traversal/walker.rs`
- Authority auditing → aadhaara `traversal/auditor.rs`
- Sync reconciliation → aadhaara `protocol/`
- Storage interface → aadhaara `state/`
- Identity, key derivation → aadhaara `identity/`

The SDK does **not** reimplement any of this. It orchestrates it.

---

**Certified by:**  
*The Akshara Council of One*
