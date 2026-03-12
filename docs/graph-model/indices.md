---
title: "Merkle-Index Specification"
subtitle: "Path Resolution and Directory Simulation in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Merkle-Index Specification

## 1. Introduction
This document describes the **Merkle-Index** structure, which provides the mechanism for resolving human-readable path sequences (e.g., `/notes/ideas.txt`) into cryptographically verifiable `Address` objects.

## 2. Structural Definition
A Merkle-Index is a specialized **Data Block** (`0x57`) with the semantic type `"index"`. 

### 2.1 Payload Schema
The encrypted `content` of an index block consists of a **BTreeMap<String, Address>** encoded in DAG-CBOR.
*   **Key:** A UTF-8 string representing a path segment.
*   **Value:** An Akshara `Address` pointing to either a leaf data node or another index node (for nested structures).

## 3. Path Resolution Algorithm
The `GraphWalker` component resolves paths through a recursive lookup process:

1.  **Input:** A `root_id` (BlockId) and a `path` string.
2.  **Normalization:** The path is cleaned of leading/trailing slashes and split into segments.
3.  **Lookup Loop:** For each segment:
    *   Fetch the block identified by the current ID.
    *   Decrypt the content using the project's `GraphKey`.
    *   Locate the segment key in the map.
    *   Update the current ID to the associated `Address`.
4.  **Verification:** At each step, the `Auditor` verifies the integrity of the fetched block.
5.  **Output:** The final `Address` identifying the resource at the end of the path.

## 4. Cycle and Depth Protection
To ensure system stability, the resolution algorithm MUST enforce the following constraints:

*   **Visited Tracking:** The walker MUST maintain a set of all `Address` objects encountered during a single resolution. If an address is repeated, a **Cycle Detected** error must be returned.
*   **Segment Limit:** Resolution MUST be terminated if the number of path segments exceeds **256**.

## 5. Path Mutation Algorithm (Bottom-Up Hashing)
To insert or update a resource at a nested path (e.g., `/a/b/c`), the system MUST perform a recursive bottom-up reconstruction of the index tree.

1.  **Leaf Creation:** Create the target data block and obtain its CID ($C_{target}$).
2.  **Leaf Index Update:** Fetch or initialize the index block for path `/a/b/`. Insert the mapping `c -> C_{target}` and obtain the new CID for this index ($C_{leaf}$).
3.  **Recursive Propagation:** Repeat Step 2 for each parent segment (e.g., `/a/`), updating the mapping to point to the new CID of the child index until the Root Index is reached.
4.  **Manifest Anchor:** Update the Manifest's `content_root` to the CID of the new Root Index.

## 6. The IndexBuilder Primitive
To simplify the mutation ritual, the foundation provides an **`IndexBuilder`** component.

*   **Responsibility:** It abstracts the complexity of nested BTreeMap creation and recursive hashing.
*   **API:**
    *   `insert(path: &str, address: Address)`: Adds a resource pointer to the virtual tree.
    *   `build(store: &impl GraphStore, signer: &impl SovereignSigner, key: &GraphKey)`: Physically constructs the Merkle-DAG by persisting the required index blocks to storage.

## 7. Metadata Separation
The Merkle-Index only facilitates **Navigation**.
 It does not contain authority or ownership information. All social laws are enforced at the **Manifest** layer, which anchors the root of the index tree.
