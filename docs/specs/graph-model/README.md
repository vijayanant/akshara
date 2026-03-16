---
title: "Graph Model Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-03-14
---

# Graph Model Specification

## 1. Motivation

### The Problem

Traditional data models are location-based, not content-based:

- **Files on disk:** Identified by path (`/home/user/doc.txt`). Move the file, the identifier breaks.
- **Database rows:** Identified by primary key. Delete and re-insert, the identifier changes.
- **Web URLs:** Identified by server location. Server goes down, the link dies.

This creates **location dependency**: data is tied to where it lives.

### The Akshara Solution

**Everything is a Graph** — specifically, a **Merkle-DAG** (Directed Acyclic Graph):

- **Content-addressed:** Data is identified by its cryptographic hash (CID)
- **Immutable:** Once created, a block never changes
- **Self-verifying:** Any tampering changes the CID, breaking the graph
- **Location-independent:** Data can live anywhere; the CID always works

```
Traditional:  /server/path/doc.txt  →  Data lives here
Akshara:      bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi  →  Data IS this hash
```

### Why Graphs?

| Benefit | Description |
|---------|-------------|
| **Offline-first** | Graphs can be edited offline, then merged mathematically |
| **Tamper-evident** | Any modification cascades to the root CID |
| **Structural sharing** | Unchanged nodes are reused, minimizing storage |
| **Conflict detection** | Concurrent edits create visible forks in the DAG |

### Design Rationale

For the full design decisions, see:
- [Cryptographic Integrity & Agility](../../docs_blueprint/core/design-decisions/cryptographic-integrity.md)
- [Platform Primitives](../../docs_blueprint/platform/primitives.md)
- [Linked Graphs](../../docs_blueprint/platform/linked-graphs.md)

---

## 2. Overview

This specification defines the Akshara Graph Model, which defines the topological and geometric laws for organizing data within a decentralized web.

### Node Taxonomy

| Node Type | Multicodec | Purpose |
|-----------|------------|---------|
| **Data Block** | `0x57` | Atomic unit of encrypted application data |
| **Graph Manifest** | `0x58` | Signed snapshot capturing graph state |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Graph Manifest (0x58)                                      │
│  - Signed by author                                         │
│  - Points to content_root (BlockId)                         │
│  - Contains identity_anchor (authority proof)               │
│  - Lists parent manifests (timeline)                        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ points to
┌─────────────────────────────────────────────────────────────┐
│  Root Index Block (0x57, type="index")                      │
│  - BTreeMap<path_segment, Address>                          │
│  - Example: { "notes": CID1, "attachments": CID2 }          │
└─────────────────────────────────────────────────────────────┘
                    │                   │
                    ▼                   ▼
            ┌───────────┐       ┌───────────┐
            │  Block    │       │  Block    │
            │  (data)   │       │  (index)  │
            └───────────┘       └───────────┘
```

### Key Concepts

| Term | Meaning |
|------|---------|
| **CID** | Content Identifier. Cryptographic hash of data. |
| **Block** | Atomic unit of data (encrypted payload + metadata) |
| **Manifest** | Signed snapshot of graph state |
| **Index** | Special block mapping paths to CIDs |
| **GraphKey** | Symmetric key for encrypting graph content |
| **Identity Anchor** | CID of Identity Graph proving author's authority |

---

## 3. Specification Structure

| Document | Purpose |
|----------|---------|
| [**Nodes**](nodes.md) | Data blocks: structure, encryption, linking |
| [**Snapshots**](snapshots.md) | Manifests: headers, signatures, timeline |
| [**Indices**](indices.md) | Merkle-Index: path resolution, directory simulation |

---

## 4. Structural Properties

| Property | Description |
|----------|-------------|
| **Merkle-DAG Integrity** | Any modification to a leaf changes the root CID |
| **Structural Sharing** | Unchanged nodes are reused across updates |
| **Acyclic Topology** | Circular references are prohibited |

---

## 5. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Tampering** | Any change modifies CID; graph becomes invalid |
| **Replay attacks** | Identity anchor proves authority at time of signing |
| **Type confusion** | Multicodec (0x57 vs 0x58) prevents block/manifest confusion |

### Assumptions

1. **Encrypted content:** Block content is encrypted before hashing (confidentiality)
2. **Authenticated encryption:** XChaCha20-Poly1305 ensures integrity
3. **Canonical encoding:** DAG-CBOR ensures consistent hashing

---

## 6. References

- [Content Identifiers (CID)](https://docs.ipfs.tech/concepts/content-addressing/)
- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
- [Multicodec Table](https://github.com/multiformats/multicodec/blob/master/table.csv)
