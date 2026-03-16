# Technical Explainer: Merkle Indexing & Hierarchical State

This note documents our move from a flat data model to a hierarchical Merkle Tree. This refactor solves the "Fat Manifest" bottleneck and enables human-readable navigation within end-to-end encrypted graphs.

## 1. The Bottleneck: The Fat Manifest
In our initial design, the `Manifest` contained a `Vec<BlockId>` of every active block in the graph.

**The Problem:**
*   **Linear Growth:** As a document grows to 10,000 blocks, the Manifest becomes huge.
*   **Sync Bloat:** Every time a single character changes, the Relay has to send the entire list of 10,000 CIDs just to identify the new state.
*   **Opaque Structure:** There was no way to organize data (e.g., "all images go in /assets") without downloading everything.

## 2. The Solution: The Merkle Index Tree
We replaced the flat list with a **Content Root**. The Manifest now points to a single CID— the root of a tree.

**New Manifest Structure:**
```rust
pub struct Manifest {
    id: ManifestId,
    content_root: BlockId, // The top-level Index Block
    identity_anchor: ManifestId,
    // ... metadata and signatures
}
```

## 3. Index Blocks (The "Directories")
We introduced a new type of block: the **Index Block**. 
An Index Block is just a Sovereign Block where the payload is a `BTreeMap<String, Cid>`.

*   **Canonical Serialization:** We use **CBOR** (`serde_cbor`) to serialize these maps. Unlike JSON, CBOR is binary-efficient and we use it to ensure keys are always sorted. This guarantees that the same directory structure always produces the same CID.
*   **Privacy:** Index blocks are encrypted with the `GraphKey`. The Relay sees a CID, but it cannot see the file names or the tree structure.

## 4. Recursive Path Resolution
We implemented `GraphWalker::resolve_path`, which allows us to find data using human-readable strings like `"/metadata/title"`.

**The Traversal Logic:**
1.  Fetch the `content_root` block.
2.  Decrypt it using the `GraphKey`.
3.  Parse the CBOR payload into a Map.
4.  Find the CID for the next path segment (e.g., `"metadata"`).
5.  Repeat until the final leaf is reached.

## 5. Security: The "Codec Gate" Pattern
During this phase, we discovered that CIDs are "Syntactically Robust" but "Semantically Dangerous." A library might accept a valid Git CID where we expected a Sovereign CID.

We implemented **Codec Gates** in our `TryFrom` wrappers:
*   **Gate 0x50:** Only allows CIDs identifying Sovereign Blocks.
*   **Gate 0x51:** Only allows CIDs identifying Sovereign Manifests.

**The Lesson learned:** Never use string-replacement logic (like `json.replace("bafy", "bafz")`) to test security. These tests pass for the wrong reasons. Always inject the wrong **Type** or **Codec Byte** directly into the parser to verify the gate.

## Summary for Implementation
*   **Scalability:** Manifest size is now constant (O(1)) regardless of graph size.
*   **Agility:** We can now organize graphs into logical folders.
*   **Integrity:** Every level of the tree is cryptographically bound to the Manifest ID.
