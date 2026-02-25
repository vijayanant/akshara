---
title: "Schema Specification"
subtitle: "Semantic Type Tagging and Resource Composition in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Schema Specification

## 1. Introduction
This document defines the semantic layer of the Akshara Graph Model. While the core protocol treats data as encrypted blobs, the **Schema** layer provides the rules for interpreting those blobs based on their declared `type`.

## 2. Reserved Codec Registry
To prevent semantic hijacking and ensure structural integrity, the **`akshara.`** namespace is reserved for core foundation types. All implementations MUST enforce a strict whitelist for these types.

| Block Type | Payload Schema | Functional Role |
| :--- | :--- | :--- |
| **`akshara.index.v1`** | `BTreeMap<String, Address>` | Directory-like path resolution. |
| **`akshara.data.v1`** | `Vec<u8>` | Raw application content. |
| **`akshara.auth.v1`** | `CborMap` | Credential authorization metadata. |
| **`akshara.revocation.v1`** | `CborMap` | Permanent credential tombstone. |
| **`akshara.trust.v1`** | `CborMap` | Cross-graph trust delegation. |
| **`akshara.succession.v1`** | `CborMap` | Ownership transfer record. |

## 3. Core Resource Schemas
Akshara defines standard composition patterns to simulate traditional data structures.

### 3.1 Resource Containers (Folders)
A folder is simulated by a block of type **`akshara.index.v1`**. It contains a map of names to `Address` objects.
*   **Recursive Navigation:** If a value in the index points to another `"index"` block, the path resolution continues.
*   **Terminal Nodes:** If a value points to a `"data"` block, the path resolution terminates.

### 3.2 Resources (Files)
A file is represented as a terminal node of type `"data"`. Large files SHOULD be partitioned into multiple `"data"` blocks linked via a parent `"index"` block to maintain optimal synchronization units.

## 4. Application-Level Schemas
Applications MAY define custom types (e.g., `"vcard"`, `"medical_record"`, `"chat_message"`) to enable semantic interoperability. 

*   **Namespace Policy:** Application-specific types SHOULD follow a reverse-DNS naming convention (e.g., `"com.example.app.record"`) to prevent collisions with core Akshara types.
*   **Opaque Logic:** The `aadhaara` foundation does not enforce application-level schemas; enforcement is the responsibility of the SDK and the high-level application logic.

## 5. Composition Invariants
1.  **Strict Type Binding:** The `type` of a block is part of its hash. An actor cannot change the semantic role of a block (e.g., turning a `"data"` block into an `"index"`) without changing its `BlockId`.
2.  **Type Validation:** Decoders MUST verify that the decrypted payload conforms to the schema associated with its declared `type` before processing.
