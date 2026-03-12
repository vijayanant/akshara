---
title: "Data Nodes Specification"
subtitle: "Structure and Recursive Linking of Akshara Blocks"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Data Nodes Specification

## 1. Introduction
This document defines the physical structure and recursive properties of **Data Blocks** (Nodes) within the Akshara Graph Model. Blocks are the atomic units of information, containing encrypted application data and the links required to form complex structures.

## 2. Node Identifier (BlockId)
All Data Blocks MUST utilize an address with the **`0x57`** multicodec. This ensures that the system can distinguish between raw data and signed snapshots at the bit-level.

## 3. Block Structure
A Block is encoded using the **Canonical DAG-CBOR** standard and consists of the following logical fields:

*   **`content`:** The encrypted application payload.
*   **`type`:** A UTF-8 string indicating the semantic role of the block (e.g., `"data"`, `"index"`, `"auth"`).
*   **`parents`:** A collection of `BlockId`s representing the immediate ancestors of the node in the content tree.
*   **`author`:** The public signing key of the credential that produced the block.
*   **`signature`:** A cryptographic signature over the `BlockId`.

## 4. Recursive Linking
Akshara enables the creation of complex resources through recursive linking. A block MAY include `Address` objects within its encrypted `content`.

### 4.1 Link Types
1.  **Structural Links (`parents`):** Defined at the block header level. These form the immutable lineage of the graph and are visible to the `Auditor` without decryption.
2.  **Content Links:** Defined within the encrypted payload. These are only visible to authorized credentials possessing the appropriate `GraphKey`.

## 5. Integrity Invariants
*   **Content Secrecy:** The `content` field MUST be encrypted using authenticated encryption (AES-GCM) at the source.
*   **Immutable Binding:** Any change to the `parents`, `type`, or `content` MUST result in a different `BlockId`.
*   **Atomic Verification:** A block is only considered valid if its `signature` is verified and its re-calculated hash matches its `BlockId`.

## 6. Depth Limit
To prevent stack exhaustion and Resource-exhaustion (DoS) attacks during traversal, recursive resolution MUST be capped at a depth of **256 segments**. Any path exceeding this limit MUST be rejected by the `GraphWalker`.
