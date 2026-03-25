---
title: "Graph Discovery and State Recovery Specification"
subtitle: "Stateless Reconstruction of User Data in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Graph Discovery and State Recovery Specification

## 1. Motivation

### The Problem

Users have multiple graphs (documents, projects, shared resources). How do they discover and recover all of them?

**Wrong approaches:**
- **Centralized registry:** Server keeps list of user's graphs (violates decentralization)
- **Manual backup:** User exports/imports graph IDs (error-prone, forgetful)
- **Device-specific:** List stored on each device (lost when device is lost)

**Requirements:**
- **Decentralized:** No central server
- **Recoverable:** 24 words restore everything
- **Private:** Relay can't cluster graphs by user
- **Automatic:** No manual bookkeeping

### The Akshara Solution

**Resource Index in Identity Graph** — a content-addressed directory of all graphs:

```
Identity Graph:
  /resources/
    /owned/
      /<graph_id_1>/ → GraphDescriptor (enc_graph_key, label, latest_manifest)
      /<graph_id_2>/ → GraphDescriptor
    /shared/
      /<graph_id_3>/ → GraphDescriptor (enc_graph_key from lockbox)

Recovery:
  1. Restore identity from 24 words
  2. Resolve /resources/ path
  3. Decrypt all GraphDescriptors
  4. Recover all graph keys
  5. Sync each graph from Relay
```

**Key properties:**
- **Deterministic:** Same 24 words → same resource list
- **Private:** Discovery ID per graph (Relay can't cluster)
- **Encrypted:** Graph keys encrypted with Keyring Secret
- **Complete:** All graphs recoverable from identity

### Design Rationale

For the full design decisions, see:
- [Tiered Identity: The Adhara of Authority](../../docs_blueprint/identity/tiered-model.md)

---

## 2. Overview

This document defines the protocols for maintaining a persistent index of a user's associated data graphs within their Identity Graph. This mechanism ensures that a user can reconstruct their entire digital state—including owned and shared graphs—using only their 256-bit entropy seed, without reliance on a centralized registry or hardware-specific backups.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Resource Index** | Directory of graphs in Identity Graph |
| **Discovery ID** | HMAC-derived identifier for finding graphs on Relay |
| **Graph Descriptor** | Metadata block with encrypted graph key |
| **Keyring Secret** | Branch 4 key for encrypting graph keys |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Resource Index Structure                                   │
│                                                             │
│  Identity Graph                                             │
│    /resources/                                              │
│      /owned/                                                │
│        /<graph_id_hex>/ → GraphDescriptor                   │
│          {                                                  │
│            graph_id: UUID,                                  │
│            latest_manifest_id: CID,                         │
│            label: "My Project",                             │
│            enc_graph_key: XChaCha20(KeyringSecret, key)     │
│          }                                                  │
│                                                             │
│      /shared/                                               │
│        /<graph_id_hex>/ → GraphDescriptor                   │
│          {                                                  │
│            graph_id: UUID,                                  │
│            enc_graph_key: XChaCha20(KeyringSecret, key),    │
│            shared_by: <pubkey>                              │
│          }                                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Discovery ID Derivation

### 3.1. Identity Graph Discovery

To locate the Identity Graph associated with a specific resource on a Relay without revealing the user's global identity, a deterministic **Lakshana** is utilized.

**Note:** The term "Discovery ID" is used interchangeably with `Lakshana` (ಲಕ್ಷಣ). The `Lakshana` type is a 32-byte anonymous identifier.

```
// Step 1: Derive the Discovery Master Key (Branch 5)
DiscoveryMasterKey = SLIP0010_Derive(MasterSeed, "m/44'/999'/0'/5'/0'/")

// Step 2: Derive the isolated Lakshana via HMAC-SHA256
Lakshana = HMAC-SHA256(
    key: DiscoveryMasterKey,
    message: "akshara.v1.discovery" || GraphId
)
```

| Property | Benefit |
|----------|---------|
| **Branch Isolation** | Master Seed is never used as an HMAC key |
| **Bound to GraphId** | Relay can't cluster graphs by user |
| **Deterministic** | Same seed + graph_id → same Lakshana |
| **One-way** | Can't derive DiscoveryMasterKey from Lakshana |
| **32 bytes** | Full HMAC-SHA256 output (not truncated) |

### 3.2. The Lakshana Type

```rust
/// `Lakshana` (ಲಕ್ಷಣ) is the anonymous, content-addressed identifier for network discovery.
///
/// Properties:
/// - 32 bytes (full HMAC-SHA256 output)
/// - Anonymous (cannot be linked to master identity)
/// - Deterministic (same GraphId → same Lakshana)
/// - Unlinkable (different GraphIds → uncorrelated Lakshanas)
pub struct Lakshana([u8; 32]);
```

**Usage:**
```rust
// Derive Lakshana for a graph
let lakshana = master_identity.derive_discovery_id(&graph_id)?;

// Query relay by Lakshana (not GraphId!)
let data = relay.query(&lakshana).await?;

// Debug display (redacted to prevent side-channel clustering)
println!("{:?}", lakshana);  // Prints: Lakshana(<REDACTED>)
```

### 3.3. Usage Examples

```
// Finding your own Identity Graph:
identity_lakshana = HMAC-SHA256(DiscoveryMasterKey, "akshara.v1.discovery")

// Finding a specific graph:
graph_lakshana = HMAC-SHA256(DiscoveryMasterKey, "akshara.v1.discovery" || graph_id)
```

---

## 4. Graph Descriptor Schema

Each entry in the Resource Index points to a **Graph Descriptor Block**.

### 4.1. Descriptor Structure

```cbor
{
  "graph_id": <16-byte UUID>,
  "latest_manifest_id": <ManifestId or null>,
  "label": <UTF-8 string or null>,
  "enc_graph_key": <encrypted bytes>,
  "keyring_version": <u64>,
  "created_at": <u64 timestamp>,
  "shared_by": <SigningPublicKey or null>  // null if owned
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `graph_id` | UUID | Yes | Stable 128-bit identifier |
| `latest_manifest_id` | ManifestId | No | Last known-good snapshot CID |
| `label` | string | No | Human-readable name (e.g., "Work Notes") |
| `enc_graph_key` | bytes | Yes | GraphKey encrypted with Keyring Secret |
| `keyring_version` | u64 | Yes | Keyring version at encryption time |
| `created_at` | u64 | Yes | Unix timestamp of registration |
| `shared_by` | pubkey | No | If shared, the sharer's public key |

### 4.2. Encryption

```
// Encrypt graph key with Keyring Secret
nonce = random_24_bytes()
enc_graph_key = XChaCha20-Poly1305-Encrypt(
    key: keyring_secret,
    nonce: nonce,
    plaintext: graph_key,
    associated_data: graph_id
)
```

---

## 5. Resource Registration Workflow

When a new graph is created or a shared invitation is accepted, the client MUST update the Identity Graph.

### 5.1. Registration Algorithm

```
Input:  graph_id, graph_key, label, master_seed, identity_signer, rng
Output: descriptor_cid, error (optional)

// Step 1: Derive Keyring Secret
1. keyring_path = "m/44'/999'/0'/4'/0'/"
   keyring_secret = SLIP0010_Derive(master_seed, keyring_path)

// Step 2: Encrypt graph key
2. nonce = random_24_bytes(rng)
   enc_graph_key = XChaCha20-Poly1305-Encrypt(
       key: keyring_secret,
       nonce: nonce,
       plaintext: graph_key,
       associated_data: graph_id
   )

// Step 3: Create descriptor
3. descriptor = {
       graph_id: graph_id,
       latest_manifest_id: null,  // Will be set on first manifest
       label: label,
       enc_graph_key: enc_graph_key,
       keyring_version: 0,
       created_at: unix_timestamp(),
       shared_by: null  // Owned graph
   }

// Step 4: Create descriptor block
4. block = {
       content: CBOR_encode(descriptor),
       type: "graph_descriptor",
       parents: [],
       author: identity_signer.public_key()
   }
5. block_cid = CID(0x57, SHA2-256(DAG-CBOR(block)))
6. signature = identity_signer.sign(block_cid)
7. block.signature = signature

// Step 5: Add to Resource Index
8. index_path = "/resources/owned/" + hex_encode(graph_id)
9. IndexBuilder.insert(index_path, block_cid)
10. root_index_cid = IndexBuilder.build(store, identity_signer)

// Step 6: Update Identity Manifest
11. identity_manifest = create_identity_manifest(
        content_root: root_index_cid,
        signer: identity_signer
    )

12. Return block_cid, nil
```

---

## 6. State Recovery Algorithm

State Recovery is the procedure for reconstructing the resource list on a fresh device.

### 6.1. Recovery Algorithm

```
Input:  mnemonic (24 words), passphrase (optional), relay
Output: recovered_graphs (list), error (optional)

// Step 1: Restore identity from mnemonic
1. seed = PBKDF2-HMAC-SHA512(normalize(mnemonic), "mnemonic" + passphrase, 2048)
2. legislator_key = SLIP0010_Derive(seed, "m/44'/999'/0'/0'/")
3. keyring_secret = SLIP0010_Derive(seed, "m/44'/999'/0'/4'/0'/")

// Step 2: Find Identity Graph on Relay
4. discovery_id = HMAC-SHA256(seed, "akshara.v1.discovery")
5. identity_heads = relay.query_by_discovery_id(discovery_id)
6. identity_manifest = resolve_latest_manifest(identity_heads)

// Step 3: Resolve Resource Index
7. resources_root = resolve_path(identity_manifest.graph, "/resources/")
   if resources_root is null:
       return [], "No resources found"

// Step 4: Iterate owned graphs
8. recovered_graphs = []
9. owned_entries = resolve_path(resources_root, "/owned/")
10. for graph_id_hex in owned_entries:
        descriptor_cid = owned_entries[graph_id_hex]
        descriptor_block = store.get_block(descriptor_cid)
        descriptor = decrypt_descriptor(descriptor_block, keyring_secret)

        recovered_graphs.push({
            graph_id: descriptor.graph_id,
            graph_key: decrypt_graph_key(descriptor, keyring_secret),
            label: descriptor.label,
            type: "owned"
        })

// Step 5: Iterate shared graphs
11. shared_entries = resolve_path(resources_root, "/shared/")
12. for graph_id_hex in shared_entries:
        // Same as owned graphs
        ...

// Step 6: Re-synchronize each graph
13. for graph in recovered_graphs:
        graph_discovery_id = HMAC-SHA256(seed, "akshara.v1.discovery" || graph.graph_id)
        graph_heads = relay.query_by_discovery_id(graph_discovery_id)
        sync_graph(graph, graph_heads)

14. Return recovered_graphs, nil
```

---

## 7. Test Vectors

### Test Vector 1: Register New Graph

```
Input:
  graph_id: 550e8400-e29b-41d4-a716-446655440000
  graph_key: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  label: "Test Project"
  mnemonic: (24 words)

Process:
  1. Derive Keyring Secret from Branch 4
  2. Encrypt graph_key with Keyring Secret
  3. Create Graph Descriptor
  4. Add to /resources/owned/<graph_id_hex>
  5. Update Identity Manifest

Expected Result:
  Descriptor block created at /resources/owned/<graph_id_hex>
  Identity Manifest updated with new content_root
```

### Test Vector 2: Recover Graphs from Seed

```
Input:
  mnemonic: (same 24 words as Test Vector 1)
  passphrase: ""

Process:
  1. Derive seed from mnemonic
  2. Find Identity Graph via Discovery ID
  3. Resolve /resources/ path
  4. Decrypt all descriptors
  5. Recover graph keys

Expected Result:
  recovered_graphs contains "Test Project"
  graph_key matches original
```

---

## 8. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Relay clustering** | Discovery ID per graph prevents clustering |
| **Key leakage** | Graph keys encrypted with Keyring Secret |
| **Lost device** | 24 words restore all graph keys |
| **Forward secrecy** | Keyring rotation re-encrypts all graph keys |

### Security Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Atomic Updates** | Graph creation + Index update MUST be atomic |
| **Credential Isolation** | Graph keys encrypted with latest Keyring Secret |
| **Discovery Privacy** | Discovery ID bound to GraphId (prevents clustering) |

### Assumptions

1. **Identity Graph availability:** Identity Graph is accessible on Relay
2. **Keyring Secret security:** Branch 4 key is not compromised
3. **Atomic registration:** SDK handles graph creation + index update atomically

### Limitations

| Limitation | Impact |
|------------|--------|
| **Floating graphs** | If index update fails, graph exists but isn't indexed |
| **Relay DoS** | Malicious relay can withhold Discovery ID responses |
| **Keyring rotation cost** | Must re-encrypt all graph keys on rotation |

---

## 9. References

- [Key Derivation Specification](derivation.md)
- [Identity Lifecycle Specification](lifecycle.md)
- [Merkle-Index Specification](../graph-model/indices.md)
