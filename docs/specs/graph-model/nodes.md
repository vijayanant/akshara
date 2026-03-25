---
title: "Data Nodes Specification"
subtitle: "Structure and Recursive Linking of Akshara Blocks"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Data Nodes Specification

## 1. Introduction

This document defines the physical structure and recursive properties of **Data Blocks** (Nodes) within the Akshara Graph Model. Blocks are the atomic units of information, containing encrypted application data and the links required to form complex structures.

### Motivation

**Why separate blocks from manifests?**

- **Blocks** = Content (encrypted, immutable data)
- **Manifests** = Authority (signed snapshots of graph state)

This separation enables:
- **Fine-grained deduplication:** Identical content produces identical block CIDs
- **Structural sharing:** Blocks are reused across manifest updates
- **Blind infrastructure:** Relays can verify block integrity without reading content

---

## 2. Node Identifier (BlockId)

All Data Blocks MUST utilize an address with the **`0x57`** multicodec. This ensures that the system can distinguish between raw data and signed snapshots at the bit-level.

### BlockId Format

```
BlockId = multicodec(0x57) || multihash(SHA2-256, DAG-CBOR(block))
```

**Example:**
```
0x57 + 0x12 + 0x20 + <32-byte hash>
│    │    └─ SHA2-256 digest length
│    └─ SHA2-256 multihash code
└─ DAG-CBOR multicodec code
```

---

## 3. Block Structure

A Block is encoded using the **Canonical DAG-CBOR** standard and consists of the following logical fields:

```cbor
{
  "content": <encrypted bytes>,      // XChaCha20-Poly1305 ciphertext
  "type": "data" | "index" | "auth", // Semantic role
  "parents": [                       // Immediate ancestors (can be empty)
    <BlockId1>,
    <BlockId2>
  ],
  "author": <SigningPublicKey>,      // Ed25519 public key
  "signature": <Signature>           // Signature over BlockId
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | bytes | Yes | Encrypted application payload |
| `type` | string | Yes | Semantic role (`"data"`, `"index"`, `"auth"`) |
| `parents` | array | Yes | Parent BlockIds (empty for root blocks) |
| `author` | bytes | Yes | Ed25519 public key of block creator |
| `signature` | bytes | Yes | Signature over the block's CID |

---

## 4. Content Encryption

### 4.1. Encryption Algorithm

**Input:**
- `plaintext`: Application data (bytes)
- `graph_key`: 32-byte symmetric key
- `graph_id`: 16-byte UUID
- `author_pubkey`: Ed25519 public key
- `block_type`: Semantic role string
- `parents`: List of parent BlockIds

**Output:**
- `ciphertext`: Encrypted data + authentication tag
- `nonce`: 24-byte nonce

**Algorithm:**
```
nonce = random_24_bytes()  // Cryptographically secure RNG

// Bind context via Associated Data (AD)
associated_data = Hash(
    "AKSHARA_V1_BLOCK_AD" || 
    graph_id || 
    author_pubkey || 
    block_type || 
    parents
)

ciphertext, tag = XChaCha20-Poly1305-Encrypt(
    key = graph_key,
    nonce = nonce,
    plaintext = plaintext,
    associated_data = associated_data
)
return ciphertext || tag, nonce
```

### 4.2. Decryption Algorithm

```
plaintext = XChaCha20-Poly1305-Decrypt(
    key = graph_key,
    nonce = nonce,
    ciphertext = ciphertext || tag,
    associated_data = associated_data
)
// Returns error if authentication tag doesn't match
```

---

## 5. Recursive Linking

Akshara enables the creation of complex resources through recursive linking. A block MAY include `Address` objects within its encrypted `content`.

### 5.1 Link Types

| Link Type | Location | Visibility |
|-----------|----------|------------|
| **Structural Links** | `parents` field | Visible to Auditor (unencrypted) |
| **Content Links** | Inside `content` | Visible only with GraphKey |

### 5.2. Example: Index Block

An index block maps human-readable paths to BlockIds:

```cbor
{
  "content": encrypted({
    "notes": <BlockId_notes>,
    "attachments": <BlockId_attachments>,
    "README.md": <BlockId_readme>
  }),
  "type": "index",
  "parents": [],
  "author": <pubkey>,
  "signature": <signature>
}
```

---

## 6. Integrity Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Content Secrecy** | `content` MUST be encrypted with XChaCha20-Poly1305 |
| **Immutable Binding** | Any change to `parents`, `type`, or `content` MUST change BlockId |
| **Atomic Verification** | Block is valid only if signature verifies AND hash matches |

---

## 7. Depth Limit

To prevent stack exhaustion and DoS attacks during traversal:

- **Maximum depth:** 256 segments
- **Enforcement:** GraphWalker MUST reject paths exceeding this limit

---

## 8. Algorithms
### 8.1. Block Creation

```
Input:  plaintext, graph_key, graph_id, block_type, parent_ids, author_signer
Output: Block (with CID and signature)

1. nonce = random_24_bytes()
2. associated_data = Hash("AKSHARA_V1_BLOCK_AD" || graph_id || author_signer.public_key() || block_type || parent_ids)
3. content = XChaCha20-Poly1305-Encrypt(plaintext, graph_key, nonce, associated_data)
4. block = {
       content: content,
       type: block_type,
       parents: parent_ids,
       author: author_signer.public_key()
   }
```
4. block_cid = CID(0x57, SHA2-256(DAG-CBOR(block)))
5. signature = author_signer.sign(block_cid)
6. block.signature = signature
7. Return block
```

### 8.2. Block Verification

```
Input:  block, expected_cid
Output: valid (bool), error (optional)

1. // Verify CID
   computed_cid = CID(0x57, SHA2-256(DAG-CBOR(block)))
   if computed_cid != expected_cid:
       return false, "CID mismatch"

2. // Verify signature
   valid = verify_signature(block.author, block.signature, expected_cid)
   if not valid:
       return false, "Invalid signature"

3. // Verify parent references exist (if parents not empty)
   for parent_id in block.parents:
       if not store.has(parent_id):
           return false, "Missing parent"

4. return true, nil
```

---

## 9. Test Vectors

### Test Vector 1: Simple Data Block

| Field | Value |
|-------|-------|
| **Plaintext** | `Hello, Akshara!` (UTF-8 bytes) |
| **Graph Key** | `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| **Nonce** | `0x000102030405060708090a0b0c0d0e0f10111213` (24 bytes) |
| **Type** | `"data"` |
| **Parents** | `[]` (empty) |
| **Block CID** | Computed from DAG-CBOR encoding |

### Test Vector 2: Index Block

| Field | Value |
|-------|-------|
| **Content** | Encrypted BTreeMap: `{ "file.txt": <BlockId> }` |
| **Type** | `"index"` |
| **Parents** | `[]` |
| **Graph Key** | (same as Test Vector 1) |

---

## 10. Security Considerations

### What Can Go Wrong

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Nonce reuse** | Ciphertext compromise | Use secure RNG; never reuse nonces |
| **Weak GraphKey** | Content decryption | Derive from BIP-39 seed, not user input |
| **Parent reference attack** | Orphan blocks | Verify parents exist before accepting block |
| **Depth exhaustion** | Stack overflow | Enforce 256-segment limit |

### Implementation Notes

1. **Canonical encoding:** DAG-CBOR ensures consistent hashing across implementations
2. **Associated data:** Use GraphID as AD to bind blocks to their graph
3. **Zeroization:** Clear plaintext from memory after encryption

---

## 11. References

- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
- [XChaCha20-Poly1305 (RFC 8439)](https://datatracker.ietf.org/doc/html/rfc8439)
- [Multicodec Table](https://github.com/multiformats/multicodec/blob/master/table.csv)
