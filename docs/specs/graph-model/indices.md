---
title: "Merkle-Index Specification"
subtitle: "Path Resolution and Directory Simulation in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Merkle-Index Specification

## 1. Motivation

### The Problem

Blocks are content-addressed by CID. But humans think in **paths**, not hashes:

- Human: "Open `/notes/meeting.md`"
- Block: "Here's `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylq`"

How do we bridge this gap?

Traditional solutions:
- **Centralized database:** Maps paths to content. Requires trusted server.
- **Filesystem:** Paths are location-based. Move the file, the path breaks.
- **Flat namespace:** No structure; just a bag of blocks.

### The Akshara Solution

**Merkle-Index** — a content-addressed directory tree:

```
Root Index (CID: 0xabc...)
├─→ "notes" → Index (CID: 0xdef...)
│              ├─→ "meeting.md" → Block (CID: 0x123...)
│              └─→ "ideas.md" → Block (CID: 0x456...)
└─→ "attachments" → Index (CID: 0xghi...)
               └─→ "logo.png" → Block (CID: 0x789...)
```

**Key properties:**
- **Content-addressed:** Index itself is a block with a CID
- **Immutable:** Changing any file changes all parent index CIDs
- **Structural sharing:** Unchanged subtrees are reused
- **Human-readable paths:** `/notes/meeting.md` resolves to a CID

### Design Rationale

For the full design decisions, see:
- [Platform Primitives: The Language of the Universal Graph](../../docs_blueprint/platform/primitives.md)

---

## 2. Overview

This document describes the **Merkle-Index** structure, which provides the mechanism for resolving human-readable path sequences (e.g., `/notes/ideas.txt`) into cryptographically verifiable `Address` objects.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Merkle-Index** | Special block (type `"index"`) mapping path segments to CIDs |
| **Path Resolution** | Walking index tree to find target block CID |
| **Bottom-Up Hashing** | Reconstructing index tree from leaf to root on updates |
| **IndexBuilder** | Helper for constructing index trees |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Merkle-Index Structure                                     │
│                                                             │
│  Manifest (0x58)                                            │
│    content_root → Root Index (0x57, type="index")           │
│                        │                                    │
│                        ├─→ "notes" → Index Block            │
│                        │      │                             │
│                        │      ├─→ "meeting.md" → Data Block │
│                        │      └─→ "ideas.md" → Data Block   │
│                        │                                    │
│                        └─→ "attachments" → Index Block      │
│                               │                             │
│                               └─→ "logo.png" → Data Block   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Structural Definition

A Merkle-Index is a specialized **Data Block** (`0x57`) with the semantic type `"index"`.

### 3.1. Block Structure

```cbor
{
  "content": <encrypted BTreeMap>,  // See schema below
  "type": "index",
  "parents": [<parent_index_cids>],
  "author": <SigningPublicKey>,
  "signature": <Signature>
}
```

### 3.2. Payload Schema

The encrypted `content` of an index block consists of a **BTreeMap<String, Address>**:

```cbor
{
  "notes": <BlockId>,           // Can point to index or data block
  "attachments": <BlockId>,
  "README.md": <BlockId>
}
```

| Field | Type | Description |
|-------|------|-------------|
| **Key** | UTF-8 string | Path segment (e.g., `"notes"`, `"README.md"`) |
| **Value** | Address (BlockId) | Points to index block or leaf data block |

### 3.3. Encryption

Index content MUST be encrypted with the graph's symmetric `GraphKey`:

```
nonce = random_24_bytes()
ciphertext = XChaCha20-Poly1305-Encrypt(
    key = graph_key,
    nonce = nonce,
    plaintext = CBOR_encode(btree_map),
    associated_data = graph_id
)
```

---

## 4. Path Resolution Algorithm

The `GraphWalker` component resolves paths through a recursive lookup process.

### 4.1. Path Normalization

```
Input:  path (string)
Output: segments (array of strings)

1. // Remove leading/trailing slashes
   path = trim(path, '/')

2. // Split on '/'
   segments = split(path, '/')

3. // Validate
   if len(segments) > MAX_DEPTH (256):
       return error, "Path too deep"

4. Return segments

// Examples:
// "/notes/meeting.md" → ["notes", "meeting.md"]
// "README.md" → ["README.md"]
// "/" → [] (root)
```

### 4.2. Path Resolution

```
Input:  root_cid, path, graph_key, store
Output: target_cid, error (optional)

1. segments = normalize_path(path)
2. current_cid = root_cid
3. visited = {}

4. for segment in segments:
       // Cycle detection
       if current_cid in visited:
           return null, "Cycle detected"
       visited.add(current_cid)

       // Fetch index block
       block = store.get_block(current_cid)
       if block is null:
           return null, "Block not found"

       // Verify block type
       if block.type != "index":
           return null, "Expected index block"

       // Decrypt content
       index_map = decrypt_index_content(block.content, graph_key)
       if error:
           return null, "Decryption failed"

       // Lookup segment
       if segment not in index_map:
           return null, "Path segment not found"

       current_cid = index_map[segment]

5. Return current_cid
```

### 4.3. Verification

At each step, the `Auditor` MUST verify:

1. **Block integrity:** CID matches content hash
2. **Signature validity:** Author's signature is valid
3. **Authority:** Author was authorized at identity anchor

---

## 5. Path Mutation Algorithm (Bottom-Up Hashing)

To insert or update a resource at a nested path, the system MUST perform recursive bottom-up reconstruction.

### 5.1. Insert Algorithm

```
Input:  root_cid, path, target_cid, graph_key, signer, store
Output: new_root_cid, error (optional)

1. segments = normalize_path(path)
2. if len(segments) == 0:
       return error, "Cannot insert at root"

3. // Create leaf index (or update existing)
4. leaf_segment = segments[-1]
5. leaf_index = fetch_or_create_index(root_cid, graph_key, store)
6. leaf_index.map[leaf_segment] = target_cid
7. leaf_cid = persist_index(leaf_index, graph_key, signer, store)

8. // Recursively update parent indices
9. current_cid = leaf_cid
10. for i from len(segments)-2 down to 0:
        segment = segments[i]

        // Fetch or create parent index
        if i == 0:
            parent_cid = root_cid
        else:
            parent = fetch_or_create_index(root_cid, graph_key, store)

        // Update mapping
        parent.map[segment] = current_cid

        // Persist
        current_cid = persist_index(parent, graph_key, signer, store)

11. Return current_cid (new root)
```

### 5.2. Example: Inserting `/a/b/c.txt`

```
Step 1: Create data block for c.txt → CID_C
Step 2: Create/update index for /a/b/ → maps "c.txt" to CID_C → CID_AB
Step 3: Create/update index for /a/ → maps "b" to CID_AB → CID_A
Step 4: Update manifest → content_root = CID_A

Result:
  Root (CID_A)
    └─→ "b" → Index (CID_AB)
              └─→ "c.txt" → Block (CID_C)
```

---

## 6. State Accumulation (CRDT Pattern)

When sealing, the index is built from **accumulated state**, not just staged operations. This ensures deterministic, commutative state evolution.

### 6.1. Sealing Algorithm

```
Input:  staged_operations, store, identity, graph_key
Output: new_manifest_id, error (optional)

// Step 1: Load current state from latest manifest
1. heads = store.get_heads(graph_id)
2. if heads.is_empty():
       current_state = {}  // Fresh graph
   else:
       current_state = load_state(heads[0])

// Step 2: Apply staged operations (CRDT merge)
3. for op in staged_operations:
       match op:
           Insert(path, data) => current_state[path] = data
           Update(path, data) => current_state[path] = data
           Delete(path)       => current_state.remove(path)

// Step 3: Build index from merged state
4. index_builder = IndexBuilder::new()
5. for (path, data) in current_state:
       block = create_block(data, graph_key, identity)
       store.put_block(block)
       index_builder.insert(path, block.id)
   
6. root_index = index_builder.build(store, identity, graph_key)

// Step 4: Create manifest
7. manifest = create_manifest(graph_id, root_index, heads, identity)
8. store.put_manifest(manifest)

9. Return manifest.id, nil
```

### 6.2. CRDT Properties

| Property | Guarantee |
|----------|-----------|
| **Deterministic** | Same operations → same state |
| **Commutative** | Operation order doesn't affect final state |
| **Idempotent** | Duplicate operations are harmless |
| **Convergent** | All peers reach same state eventually |

### 6.3. Benefits

- **Multiple seals accumulate** — Each seal adds to previous state
- **No data loss** — Old data persists unless explicitly deleted
- **Predictable** — Same operations always produce same result

---

## 7. The IndexBuilder Primitive

The **`IndexBuilder`** abstracts the complexity of nested BTreeMap creation and recursive hashing.

### 7.1. API

```rust
pub struct IndexBuilder {
    // Internal virtual tree structure
}

impl IndexBuilder {
    /// Add a resource to the virtual tree
    pub fn insert(&mut self, path: &str, address: Address);

    /// Build the physical Merkle-DAG
    pub fn build(
        self,
        store: &impl GraphStore,
        signer: &impl AksharaSigner,
        key: &GraphKey
    ) -> Result<BlockId>;
}
```

### 6.2. Usage Example

```rust
let mut builder = IndexBuilder::new();

// Add resources
builder.insert("notes/meeting.md", cid_meeting);
builder.insert("notes/ideas.md", cid_ideas);
builder.insert("attachments/logo.png", cid_logo);

// Build the index tree
let root_cid = builder.build(&store, &signer, &graph_key)?;

// Update manifest with new root
let manifest = Manifest::new(graph_id, root_cid, parents, anchor, &signer);
```

---

## 7. Cycle and Depth Protection

To ensure system stability, the resolution algorithm MUST enforce:

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| **Visited Tracking** | Detect cycles | Prevents infinite loops |
| **Segment Limit** | 256 segments max | Prevents stack exhaustion |

### Error Handling

```
if cycle_detected:
    return Error::CycleDetected

if path_too_deep:
    return Error::PathTooDeep

if segment_not_found:
    return Error::PathNotFound
```

---

## 8. Test Vectors

### Test Vector 1: Simple Path Resolution

```
Index Structure:
  Root Index (CID: 0xabc...)
    "notes" → Block (CID: 0xdef...)
    "README.md" → Block (CID: 0x123...)

Path: "/notes"
Expected Result: CID 0xdef...
```

### Test Vector 2: Nested Path Resolution

```
Index Structure:
  Root Index (CID: 0xabc...)
    "notes" → Index (CID: 0xdef...)
      "meeting.md" → Block (CID: 0x456...)
      "ideas.md" → Block (CID: 0x789...)

Path: "/notes/meeting.md"
Expected Result: CID 0x456...
```

### Test Vector 3: Path Not Found

```
Index Structure:
  Root Index (CID: 0xabc...)
    "notes" → Block (CID: 0xdef...)

Path: "/attachments/logo.png"
Expected Result: Error::PathNotFound
```

### Test Vector 4: Cycle Detection

```
Malicious Index:
  Root Index → "a" → Index A
  Index A → "b" → Index B
  Index B → "a" → Index A  (cycle!)

Path: "/a/b/a/b"
Expected Result: Error::CycleDetected
```

---

## 9. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Path traversal attacks** | Strict path normalization; no `..` segments |
| **Cycle attacks** | Visited tracking; cycle detection |
| **Depth exhaustion** | 256-segment limit |
| **Tampering** | Content-addressed; any change modifies CID |

### Assumptions

1. **Encrypted content:** Index content is encrypted with GraphKey
2. **Authenticated encryption:** XChaCha20-Poly1305 ensures integrity
3. **Honest builder:** IndexBuilder constructs valid trees

### Limitations

| Limitation | Impact |
|------------|--------|
| **Full rebuild on update** | Changing one file requires rebuilding all parent indices |
| **No partial resolution** | Must walk from root; can't jump to subtree |
| **Metadata visible** | Index structure (file names) visible with GraphKey |

---

## 10. References

- [Data Nodes Specification](nodes.md)
- [Graph Snapshots Specification](snapshots.md)
- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
