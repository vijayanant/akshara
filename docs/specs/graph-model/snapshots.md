---
title: "Graph Snapshots Specification"
subtitle: "Manifests and Timeline Integrity in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Graph Snapshots Specification

## 1. Motivation

### The Problem

Blocks alone don't answer critical questions:

- **Who authorized this?** A block has an author, but were they authorized?
- **When was this created?** What's the timeline of changes?
- **Which version is current?** Multiple concurrent edits create forks.

Blocks are content. We need a separate mechanism for **authority** and **timeline**.

### The Akshara Solution

**Manifests** are signed snapshots that:

- **Bind content to authority:** "I, Alice, authorize this content root at this moment"
- **Establish timeline:** "This manifest builds on these parent manifests"
- **Enable sync:** "My graph head is at this manifest CID"
- **Prove authorization:** "My Identity Graph at this anchor proves I had authority"

```
Block:  "Here is encrypted content"
Manifest: "I am authorized to publish this content, and here's my Identity Graph as proof"
```

### Design Rationale

For the full design decisions, see:
- [Causality and Time](../../docs_blueprint/synchronization/causality-and-time.md)
- [Governance & Constitutional Access](../../docs_blueprint/core/design-decisions/governance-and-access.md)

---

## 2. Overview

This specification defines the structure and verification rules for **Graph Manifests** (Snapshots). Manifests are signed metadata nodes that establish the authoritative "Head" of a graph at a specific point in time.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Manifest** | Signed snapshot of graph state |
| **Content Root** | CID of the top-level block in the graph |
| **Identity Anchor** | CID of Identity Graph proving authority |
| **Parents** | Previous manifest CIDs (timeline) |
| **Genesis** | First manifest (no parents) |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Graph Manifest (0x58)                                      │
│                                                             │
│  Header:                                                    │
│  - graph_id: "550e8400-e29b-41d4-a716-446655440000"        │
│  - content_root: bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylq  │
│  - parents: [bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylp]     │
│  - identity_anchor: bafybeigdyrzt5sfp7udm7hu76uh7y26nf3ef   │
│  - created_at: 1710422400                                  │
│                                                             │
│  author: ed25519:pubkey                                     │
│  signature: ed25519:signature                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Manifest Identifier (ManifestId)

All Graph Manifests MUST utilize an address with the **`0x58`** multicodec. This prevents type-confusion attacks where a data block could be mistaken for an authoritative snapshot.

### ManifestId Format

```
ManifestId = multicodec(0x58) || multihash(SHA2-256, DAG-CBOR(header))
```

**Note:** The signature is NOT included in the CID calculation. The CID is over the header only; the signature proves the author signed that CID.

---

## 4. Manifest Structure

A Manifest is encoded using **Canonical DAG-CBOR** and consists of:

```cbor
{
  "header": {
    "graph_id": <UUID bytes>,           // 16-byte UUID
    "content_root": <BlockId>,          // CID of root block
    "parents": [<ManifestId>, ...],     // Previous manifests (empty for genesis)
    "identity_anchor": <ManifestId>,    // Identity Graph CID (0x00...00 for genesis)
    "signer_path": <bytes>,             // SHA2-256 hash of the BIP-32 path
    "created_at": <u64>                 // Unix timestamp (metadata only)
  },
  "author": <SigningPublicKey>,         // Ed25519 public key
  "signature": <Signature>              // Signature over header CID
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `graph_id` | bytes | Yes | 128-bit UUID identifying the graph |
| `content_root` | BlockId | Yes | CID of the top-level block |
| `parents` | array | Yes | Previous ManifestIds (empty = genesis) |
| `identity_anchor` | ManifestId | Yes | Identity Graph CID (null = 0x00...00) |
| `signer_path` | bytes | Yes | **Obfuscated Path:** SHA2-256 hash of the BIP-32 path used to derive the author key |
| `created_at` | u64 | Yes | Unix timestamp (informational only) |
| `author` | bytes | Yes | The **Shadow Signing Key** (Graph-Isolated) |
| `signature` | bytes | Yes | Signature over header CID |

---

## 5. Timeline Semantics

### 5.1. Genesis Manifest

The first manifest in a graph has:
- `parents`: `[]` (empty)
- `identity_anchor`: `0x00...00` (32 zero bytes)

**Genesis Rule:** A genesis manifest MUST be signed by a key derived from the **Legislator Branch** (`m/44'/999'/0'/0'/`) of the identity. Note: Legislator actions MAY use long-term keys as they are administrative, but day-to-day **Executive** actions MUST use Shadow Keys.

### 5.2. Sequential Update

A manifest with one parent represents a linear update:

```
Manifest A → Manifest B → Manifest C
              (B lists A as parent)
              (C lists B as parent)
```

### 5.3. Merge (Concurrent Convergence)

A manifest with multiple parents represents a merge of concurrent edits:

```
Manifest A → Manifest C
           ↘         (C lists both A and B as parents)
Manifest B →
```

### 5.4. Fork (Unmerged Concurrency)

Two manifests with a common ancestor but no merge represent concurrent, unmerged edits:

```
         → Manifest B
Manifest A
         → Manifest C

(B and C are concurrent; conflict resolution required)
```

**Conflict Resolution:** The manifest with the **lexicographically lower CID** takes precedence. Both remain in the DAG for potential manual merge.

---

## 6. Authority Binding

Every manifest is cryptographically bound to an **Identity Graph**. The `identity_anchor` provides the context for the `Auditor` to perform the causal walk required to verify the author's credentials at the moment the snapshot was created.

### 6.1. Authority Verification

To verify a manifest:

1. Resolve the Identity Graph at `identity_anchor`
2. Verify the `author` key was authorized at that anchor point
3. Verify the `author` key was NOT revoked at that anchor point
4. Verify the signature over the header CID

Any manifest signed by a credential that was revoked or unauthorized at the point of the `identity_anchor` MUST be rejected as invalid.

---

## 7. Algorithms

### 7.1. Manifest Creation

```
Input:  graph_id, content_root_cid, parent_manifest_ids, identity_anchor_cid, author_signer
Output: Manifest (with CID and signature)

1. header = {
       graph_id: graph_id,
       content_root: content_root_cid,
       parents: parent_manifest_ids,
       identity_anchor: identity_anchor_cid,
       signer_path: SHA2-256(author_signer.derivation_path()),
       created_at: unix_timestamp()  // Informational only
   }

2. header_cid = CID(0x58, SHA2-256(DAG-CBOR(header)))
```
3. signature = author_signer.sign(header_cid)

4. manifest = {
       header: header,
       author: author_signer.public_key(),
       signature: signature
   }

5. Return manifest
```

### 7.2. Manifest Verification

```
Input:  manifest, auditor, store
Output: valid (bool), error (optional)

1. // Verify header CID
   header_cid = CID(0x58, SHA2-256(DAG-CBOR(manifest.header)))

2. // Verify signature
   valid = verify_signature(manifest.author, manifest.signature, header_cid)
   if not valid:
       return false, "Invalid signature"

3. // Verify identity anchor authority
   authorized = auditor.verify_authority(
       author = manifest.author,
       identity_anchor = manifest.header.identity_anchor,
       action = "sign_manifest"
   )
   if not authorized:
       return false, "Author not authorized at anchor"

4. // Verify parents exist (if not genesis)
   if manifest.header.parents is not empty:
       for parent_id in manifest.header.parents:
           if not store.has_manifest(parent_id):
               return false, "Missing parent manifest"

5. return true, nil
```

---

## 8. Test Vectors

### Test Vector 1: Genesis Manifest

| Field | Value |
|-------|-------|
| **graph_id** | `550e8400-e29b-41d4-a716-446655440000` (example UUID) |
| **content_root** | `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi` (example CID) |
| **parents** | `[]` (empty) |
| **identity_anchor** | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| **author** | Legislator-derived key |
| **signature** | Ed25519 signature over header CID |

### Test Vector 2: Sequential Update

| Field | Value |
|-------|-------|
| **graph_id** | (same as Test Vector 1) |
| **content_root** | (new CID after update) |
| **parents** | `[<genesis_manifest_cid>]` |
| **identity_anchor** | (current Identity Graph CID) |
| **author** | Executive-derived key |

---

## 9. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Unauthorized writes** | Identity anchor proves authority |
| **Replay attacks** | Identity anchor is time-bound (specific graph state) |
| **Timeline rewriting** | Parent CIDs create immutable chain |
| **Type confusion** | Multicodec 0x58 distinguishes from blocks (0x57) |

### Assumptions

1. **Honest SDK:** SDK performs authority verification correctly
2. **Identity Graph availability:** Identity Graph at anchor must be accessible for verification
3. **Clock is metadata:** `created_at` is NOT used for security decisions (causal time via parents is authoritative)

### Limitations

| Limitation | Impact |
|------------|--------|
| **Identity Graph unavailable** | Cannot verify authority; sync blocked |
| **Fork resolution** | Lower-CID wins may discard valid work |
| **Timestamp unreliable** | `created_at` can be falsified; use parent linkage for ordering |

---

## 10. References

- [Authority Verification Specification](../identity/authority.md)
- [Content Identifiers (CID)](https://docs.ipfs.tech/concepts/content-addressing/)
- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
