---
title: "Authority Verification Specification"
subtitle: "Identity Graph Auditing and Causal Trust in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Authority Verification Specification

## 1. Motivation

### The Problem

In traditional systems, authorization is **binary and static**:

- You're either on the access control list, or you're not
- Revocation requires a central server to check
- Stolen keys work forever (no way to revoke)

In a decentralized system, we need **temporal and contextual** authorization:

- "Was this key authorized **at this specific moment**?"
- "Has this key been revoked **since this action**?"
- "Does this key have authority for **this specific action**?"

### The Akshara Solution

**The Identity Graph** — an append-only, content-addressed timeline of authority:

```
Identity Graph:
  /credentials/<pubkey>  → "This key was authorized"
  /revocations/<pubkey>  → "This key was revoked"
  
To verify a signature:
  1. Resolve Identity Graph at anchor point
  2. Check: Was key authorized at this point?
  3. Check: Was key NOT revoked at this point?
  4. Accept or reject based on graph state
```

**Key insight:** Authorization is not a yes/no question. It's a **function of graph state**.

### Design Rationale

For the full design decisions, see:
- [Identity Graph: The Timeline of Authority](../../docs_blueprint/identity/identity-graph.md)
- [Tiered Identity & Durable Authority](../../docs_blueprint/core/design-decisions/identity-and-authority.md)

---

## 2. Overview

This document defines the algorithm for verifying the cryptographic authority of a signer within the Akshara ecosystem. Unlike static PKI systems, Akshara uses a temporal, content-addressed **Identity Graph** to prove the "Right to Sign" at any given point in history.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Identity Graph** | Merkle-DAG of authorization and revocation events |
| **Identity Anchor** | CID of Identity Graph manifest at verification point |
| **Causal Walk** | Traversal of Identity Graph to verify authority |
| **Credential** | Authorization block for a specific public key |
| **Revocation** | Tombstone block that permanently invalidates a credential |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Identity Graph Structure                                   │
│                                                             │
│  /credentials/                                              │
│    /ed25519:abc123...  →  Authorization Block              │
│      - derivation_path: "m/44'/999'/0'/1'/0'/              │
│      - capabilities: ["sign_manifests"]                    │
│      - authorized_at: <CID>                                 │
│                                                             │
│  /revocations/                                              │
│    /ed25519:abc123...  →  Revocation Block                 │
│      - revoked_at: <CID>                                    │
│      - reason: "device_lost"                                │
│                                                             │
│  /capabilities/                                             │
│    /ed25519:abc123...  →  Scoped Permissions               │
│      - paths: ["/notes/*", "/attachments/*"]               │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Identity Graph Structure

The Identity Graph is a Merkle-DAG representing the authorization history of an identity. It utilizes a standard directory-like hierarchy encoded in DAG-CBOR:

| Path | Purpose |
|------|---------|
| `/credentials/<public_key_hex>` | Authorization blocks for Executive keys |
| `/revocations/<public_key_hex>` | Tombstone blocks for revoked keys |
| `/capabilities/<public_key_hex>` | Scoped path permissions |

### Credential Block Schema

```cbor
{
  "type": "credential",
  "public_key": <Ed25519 public key>,
  "derivation_path": "m/44'/999'/0'/1'/<index>'/",
  "capabilities": ["sign_manifests"],
  "label": "MacBook Pro 2024",
  "authorized_at": <CID of authorization manifest>
}
```

### Revocation Block Schema

```cbor
{
  "type": "revocation",
  "target_public_key": <Ed25519 public key>,
  "reason": "device_lost" | "compromised" | "retired",
  "revoked_at": <CID of revocation manifest>
}
```

---

## 4. Authority Verification Algorithm

### 4.1. The Causal Walk

To verify a signature on a graph manifest, the `Auditor` must perform a causal walk of the Identity Graph starting from the `identity_anchor` provided in the manifest.
### 4.2. Verification Algorithm

```
Input:  signature S, public key P, manifest M, identity_anchor A, store, known_identity_history
Output: valid (bool), error (optional)

// Step 1: Verify signature integrity
1.1 valid_sig = verify_signature(P, S, M.cid)
    if not valid_sig:
        return false, "Invalid signature"

// Step 2: Resolve identity anchor
2.1 anchor_manifest = store.get_manifest(A)
    if anchor_manifest is null:
        return false, "Identity anchor not found"

// Step 3: Check credential existence at anchor
3.1 cred_path = "/credentials/" + hex_encode(P)
3.2 credential = resolve_path(anchor_manifest.graph, cred_path)
    if credential is null:
        return false, "Credential not authorized at anchor"

// Step 4: THE FRONTIER RULE: Check for revocation in ALL known history
// This prevents "Ghost Authority" attacks using stolen devices and old anchors.
4.1 for identity_manifest in known_identity_history:
        revocation_path = "/revocations/" + hex_encode(P)
        revocation = resolve_path(identity_manifest.graph, revocation_path)
        if revocation is not null:
            return false, "Credential has been revoked in the current frontier"

// Step 5: Verify derivation path matches action
...
```
5.2 valid_path = verify_derivation_path(credential.derivation_path, action)
    if not valid_path:
        return false, "Invalid derivation path for action"

// Step 6: Verify genesis binding (if null anchor)
6.1 if A == 0x00...00:  // Genesis manifest
       valid_genesis = verify_legislator_key(P)
       if not valid_genesis:
           return false, "Genesis must be signed by Legislator"

return true, nil
```

### 4.3. Path Resolution

```
Input:  graph_root (CID), path (string), graph_key
Output: content (CBOR), error (optional)

1. segments = split_path(path)  // e.g., "/credentials/abc123" → ["credentials", "abc123"]
2. current_cid = graph_root
3. visited = {}

4. for segment in segments:
       if current_cid in visited:
           return null, "Cycle detected"
       visited.add(current_cid)

       block = store.get_block(current_cid)
       if block is null:
           return null, "Block not found"

       content = decrypt(block.content, graph_key)
       if content is error:
           return null, "Decryption failed"

       if segment not in content.map:
           return null, "Path segment not found"

       current_cid = content.map[segment]

5. return content, nil
```

---

## 5. Conflict Resolution

The Identity Graph is a Directed Acyclic Graph (DAG). In scenarios where concurrent updates occur (e.g., two authorized devices modify the graph simultaneously), multiple "heads" may exist.

### 5.1. Deterministic Tie-Breaking

| Scenario | Resolution |
|----------|------------|
| **Causal fork** | Branch with **numerically lower CID** takes precedence |
| **Concurrent authorization + revocation** | Authorization wins if it's in the lower-CID branch |

**Why this works:** All peers independently arrive at the same authoritative state without coordination.

### 5.2. Example

```
Identity Graph Fork:

         → Manifest B (CID: 0xabc...)
Manifest A
         → Manifest C (CID: 0xdef...)

If B.revokes(key_X) and C.authorizes(key_X):
  - Compare CID(B) vs CID(C)
  - Lower CID wins
  - All peers converge on same result
```

---

## 6. Path-to-Purpose Enforcement

The `Auditor` enforces strict functional isolation based on the BIP-32 derivation path of the signer:

| Action | Required Derivation Path | Branch |
|--------|-------------------------|--------|
| **Authorize Credential** | `m/44'/999'/0'/0'/` | Legislator (Branch 0) |
| **Revoke Credential** | `m/44'/999'/0'/0'/` | Legislator (Branch 0) |
| **Sign Graph Manifest** | `m/44'/999'/0'/1'/...` | Executive (Branch 1) |
| **Update Capability** | `m/44'/999'/0'/0'/` | Legislator (Branch 0) |
| **Derive Graph Key** | `m/44'/999'/0'/2'/...` | Secret (Branch 2) |
| **Derive Pre-Key** | `m/44'/999'/0'/3'/...` | Handshake (Branch 3) |

**Enforcement:** If a key from Branch 1 attempts to authorize a new credential, the Auditor MUST reject the action.

---

## 7. Audit Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Causal Precedence** | `created_at` timestamp MUST be ignored for security decisions. Validity is determined solely by Merkle-linkage. |
| **The Frontier Rule** | Authority verification MUST check for revocations in the **entire known history** of the identity. A key revoked in any branch of the identity is considered globally dead. |
| **Temporal Immutability** | An authority proof is only valid for the specific CID of the identity anchor. |
| **Strict Revocation** | A revocation block is a "Permanent Tombstone." Once a key is recorded in `/revocations/`, it can never be re-authorized within that identity sub-tree. |
| **Genesis Binding** | A genesis manifest (null anchor) MUST be signed by a Legislator-derived key (Branch 0). |

---

## 8. Test Vectors

### Test Vector 1: Valid Signature Verification

| Field | Value |
|-------|-------|
| **Public Key** | `ed25519:abc123...` (example) |
| **Identity Anchor** | `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylq` (example CID) |
| **Credential Path** | `/credentials/abc123...` |
| **Revocation Path** | `/revocations/abc123...` (does not exist) |
| **Expected Result** | `valid = true` |

### Test Vector 2: Revoked Key

| Field | Value |
|-------|-------|
| **Public Key** | `ed25519:def456...` (example) |
| **Identity Anchor** | (same as Test Vector 1) |
| **Credential Path** | `/credentials/def456...` (exists) |
| **Revocation Path** | `/revocations/def456...` (exists) |
| **Expected Result** | `valid = false`, error = "Credential has been revoked" |

### Test Vector 3: Missing Credential

| Field | Value |
|-------|-------|
| **Public Key** | `ed25519:ghi789...` (example) |
| **Identity Anchor** | (same as Test Vector 1) |
| **Credential Path** | `/credentials/ghi789...` (does not exist) |
| **Expected Result** | `valid = false`, error = "Credential not found" |

### Test Vector 4: Genesis Manifest

| Field | Value |
|-------|-------|
| **Identity Anchor** | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| **Signer Path** | `m/44'/999'/0'/0'/` (Legislator) |
| **Expected Result** | `valid = true` |

### Test Vector 5: Wrong Branch for Action

| Field | Value |
|-------|-------|
| **Action** | `authorize_credential` |
| **Signer Path** | `m/44'/999'/0'/1'/0'/` (Executive) |
| **Expected Result** | `valid = false`, error = "Invalid derivation path for action" |

---

## 9. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Stolen key usage** | Revocation invalidates key across all graphs |
| **Unauthorized writes** | Credential check before accepting signature |
| **Replay attacks** | Identity anchor is time-bound |
| **Byzantine clock attacks** | `created_at` ignored; causal time via Merkle links |

### Assumptions

1. **Identity Graph availability:** The Identity Graph at anchor must be accessible
2. **Honest SDK:** SDK performs verification correctly
3. **Deterministic resolution:** All peers resolve paths identically

### Limitations

| Limitation | Impact |
|------------|--------|
| **Graph unavailable** | Cannot verify authority; sync blocked |
| **Revocation propagation delay** | Window between compromise and revocation |
| **Fork resolution** | Lower-CID wins may discard valid revocation |

---

## 10. References

- [Key Derivation Specification](derivation.md)
- [Credential Lifecycle Specification](lifecycle.md)
- [Graph Snapshots Specification](../graph-model/snapshots.md)
