---
title: "Schema Registry Specification"
subtitle: "Pattern Governance and Global Coordinate Laws"
version: "0.1.0-alpha.2"
status: "Planned — Proposed for v0.2"
date: "2026-04-23"
---

# Schema Registry Specification

> [!NOTE]
> Pattern reconnaissance (lazy field filtering during sync reconciliation) described in Section 5 of this specification is part of the Akshara Protocol standard, but is not yet implemented in the Rust reference implementation.

## 1. Motivation

To build a **Permanent Ecosystem**, we must ensure that the bits of a document remain meaningful even after the original application's source code is lost. 

A **Schema Graph** serves as the "Physical Blueprint" for a document pattern. It allows the SDK to understand the geography of a graph (which atoms are inlined, chunked, or lazy) without needing the specific L2 App's Rust code.

## 2. The Schema Anchor

Every `Manifest` MAY include a `schema_anchor`. 

*   **Null Anchor (0x00...):** The graph uses **Ad-hoc Layout**. The L2 App is the sole source of truth for the physical layout. (Recommended for single-user prototypes).
*   **Active Anchor:** Points to an `akshara.schema.v1` block. The SDK MUST follow the rules defined in this block during sync, write, and resolution rituals.

## 3. Schema Block Schema (`akshara.schema.v1`)

A Schema Block is a specialized **Data Block** (`0x57`) encoded in DAG-CBOR.

```cbor
{
  "type_name": "PatientRecord",
  "version": 1,
  "fields": [
    {
      "path": "meta/name",
      "mode": "inline",
      "type_tag": "string"
    },
    {
      "path": "imaging",
      "mode": "chunked",
      "is_lazy": true,
      "chunk_size": 1048576
    },
    {
      "path": "consultations",
      "mode": "collection"
    }
  ]
}
```

### 3.1 Field Modes

| Mode | Physical Requirement |
| :--- | :--- |
| **`inline`** | The value is embedded directly in the `BTreeMap` of the parent index block. |
| **`block`** | The value is stored as a standalone block. The index contains its CID. |
| **`collection`** | The coordinate represents a list managed via Fractional Indexing. |
| **`chunked`** | The value is split into a sub-Merkle tree. |

## 4. Operational Invariants (Shadow Path Defenses)

### 4.1 The Law of Bundling
A Relay SHOULD reject any manifest whose `schema_anchor` points to a CID that the Relay does not possess. This prevents "Orphan Law" Denial-of-Service attacks.

### 4.2 The Physical Cap
An `akshara.schema.v1` block MUST NOT exceed **64 KB**. This prevents memory-exhaustion attacks during the "Pattern Reconnaissance" phase of sync.

### 4.3 Schema Immutability
Once a Data Graph is anchored to a specific `schema_anchor`, the `mode` of existing fields MUST NOT be changed in future schema versions. Changing a mode (e.g., from `block` to `inline`) requires a formal **Migration Manifest** signed by the Legislator.

## 5. Pattern Reconnaissance (Sync)

During synchronization, if a `schema_anchor` is present:
1.  The SDK fetches the schema block FIRST.
2.  The SDK uses the schema to identify `#[lazy]` coordinates.
3.  The SDK instructs the `Reconciler` to exclude any CIDs reachable only through lazy coordinates.

***

**Architect’s Note:** *This is the 'Legend' of our map. It ensures that Akshara data is self-describing, language-agnostic, and future-proof.*
