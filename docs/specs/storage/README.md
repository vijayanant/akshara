---
title: "Storage Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Storage Specification

## 1. Motivation

### The Problem

Where do blocks and manifests live?

- **Not in memory:** Must survive restarts
- **Not tied to filesystem:** Must work on mobile, web, server
- **Not centralized:** Must support P2P, multi-relay
- **Content-addressed:** Looked up by CID, not path

### The Akshara Solution

**GraphStore abstraction** — a trait-based interface:

```rust
trait GraphStore {
    async fn get(&self, cid: &CID) -> Option<Bytes>;
    async fn put(&mut self, cid: &CID, data: Bytes);
    async fn has(&self, cid: &CID) -> bool;
    async fn heads(&self, graph_id: &GraphId) -> Vec<CID>;
    async fn set_heads(&mut self, graph_id: &GraphId, heads: Vec<CID>);
}
```

**Implementations:**
- `InMemoryStore` — Testing, caching
- `SqliteStore` — Mobile, desktop persistence
- `RelayStore` — Server-side storage
- `IPFSStore` — Distributed storage

**Key properties:**
- **Pluggable:** Swap storage backends without changing core logic
- **Content-addressed:** All lookups by CID
- **Head tracking:** Track manifest heads per graph

---

## 2. Overview

This specification defines the storage interface and operational laws for persisting and retrieving content-addressed bitstreams.

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
└─────────────────────────────────────────────────────────────┘
                          │
                          │ GraphStore trait
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Storage Implementations                                    │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ InMemory    │  │ SQLite      │  │ Relay       │         │
│  │ (testing)   │  │ (persistence)│  │ (server)    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐                          │
│  │ IPFS        │  │ S3          │                          │
│  │ (distributed)│  │ (cloud)     │                          │
│  └─────────────┘  └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Specification Structure

| Document | Purpose |
|----------|---------|
| [**Interface**](interface.md) | GraphStore trait definition |
| [**Semantics**](semantics.md) | Head management, pruning |

---

## 4. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Data corruption** | CID verification on read |
| **Head tampering** | Heads stored locally (not on relay) |
| **DoS via storage** | Quotas, limits per graph |

### Assumptions

1. **Storage durability:** Backend persists data reliably
2. **CID integrity:** Storage doesn't modify content
3. **Head security:** Heads registry protected from tampering

---

## 5. References

- [Graph Model Specification](../graph-model/README.md)
- [Synchronization Specification](../synchronization/README.md)
