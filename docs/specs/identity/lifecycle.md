---
title: "Identity Lifecycle Specification"
subtitle: "Protocols for Authorization, Revocation, and Recovery in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Identity Lifecycle Specification

## 1. Motivation

### The Problem

Identity management in decentralized systems faces unique challenges:

- **No central admin:** Can't call support to reset password
- **Device loss:** Phone stolen, laptop broken
- **Key compromise:** Malware steals private keys
- **First-time setup:** How do you create an identity from nothing?

Traditional solutions rely on centralized authorities:
- "Forgot password?" email
- SMS verification
- Security questions
- Admin reset

These don't work in a decentralized system.

### The Akshara Solution

**Identity Rituals** — deterministic procedures for the full lifecycle:

```
Birth (Genesis):     24 words → Master Key → Identity Graph
Authorization:       Legislator Key → Authorize device key
Revocation:          Legislator Key → Revoke compromised device
Correction:          Legislator Key → Prune malicious branch
Recovery:            24 words → Restore everything
```

**Key properties:**
- **Self-sovereign:** No central authority needed
- **Deterministic:** Same inputs → same outputs
- **Recoverable:** 24 words restore full identity
- **Revocable:** Lost devices can be invalidated

### Design Rationale

For the full design decisions, see:
- [Identity Graph: The Timeline of Authority](../../docs_blueprint/identity/identity-graph.md)
- [Tiered Identity: The Adhara of Authority](../../docs_blueprint/identity/tiered-model.md)

---

## 2. Overview

This document defines the formal procedures for managing an Akshara identity throughout its operational lifespan. These rituals ensure the secure delegation of authority from the Master Root to specific hardware credentials and provide the mechanism for recovery in the event of compromise or loss.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Genesis** | Initial identity creation from 24 words |
| **Authorization** | Delegating authority to a new device |
| **Revocation** | Invalidating a compromised device |
| **Correction** | Pruning malicious history after compromise |
| **Recovery** | Restoring identity from 24 words |

### Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Identity Lifecycle                                         │
│                                                             │
│  [24 words]                                                 │
│       ↓                                                     │
│  ┌─────────────────┐                                        │
│  │ 1. Genesis      │ → Identity Graph (empty)               │
│  └─────────────────┘                                        │
│       ↓                                                     │
│  ┌─────────────────┐                                        │
│  │ 2. Authorization│ → Add device to identity               │
│  └─────────────────┘                                        │
│       ↓ (repeat for each device)                            │
│  ┌─────────────────┐                                        │
│  │ 3. Revocation   │ → Remove compromised device            │
│  └─────────────────┘                                        │
│       ↓ (if needed)                                         │
│  ┌─────────────────┐                                        │
│  │ 4. Correction   │ → Prune malicious history              │
│  └─────────────────┘                                        │
│                                                             │
│  [Lost everything]                                          │
│       ↓                                                     │
│  ┌─────────────────┐                                        │
│  │ 5. Recovery     │ → Restore from 24 words                │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Ritual of Birth (Genesis)

Identity creation is the process of generating the 256-bit entropy seed and establishing the first Legislator Manifest.

### 3.1. Genesis Algorithm

```
Input:  rng (secure random number generator)
Output: mnemonic (24 words), identity_graph_root (CID)

// Step 1: Generate entropy
1. entropy = rng.generate_bytes(32)  // 256 bits

// Step 2: Create mnemonic
2. mnemonic = BIP39_FromEntropy(entropy)
   // Example: "abandon abandon... art"

// Step 3: Derive master seed
3. seed = PBKDF2-HMAC-SHA512(
       password = mnemonic,
       salt = "mnemonic",
       iterations = 2048
   )

// Step 4: Derive Legislator key
4. legislator_path = "m/44'/999'/0'/0'/"
   legislator_key = SLIP0010_Derive(seed, legislator_path)

// Step 5: Create genesis manifest
5. genesis_header = {
       graph_id: generate_uuid(),
       content_root: empty_index_cid,  // Empty index block
       parents: [],  // No parents (genesis)
       identity_anchor: 0x00...00,  // Null anchor
       created_at: unix_timestamp()
   }

6. genesis_cid = CID(0x58, SHA2-256(DAG-CBOR(genesis_header)))
7. signature = legislator_key.sign(genesis_cid)

8. genesis_manifest = {
       header: genesis_header,
       author: legislator_key.public_key(),
       signature: signature
   }

9. Return mnemonic, genesis_manifest.cid
```

---

## 4. Ritual of Authorization (Credential Onboarding)

Authorization delegates "Executive Authority" to a specific piece of hardware or role.

### 4.1. Authorization Algorithm

```
Input:  legislator_signer, new_device_info, master_seed, rng
Output: authorization_block_cid, error (optional)

// Step 1: Generate device keys
1. device_signing_key = Ed25519_keypair(rng)
   device_encryption_key = X25519_keypair(rng)

// Step 2: Derive path for this device
2. device_index = get_next_device_index()
   derivation_path = "m/44'/999'/0'/1'/" + device_index + "'/"

// Step 3: Derive Keyring Secret (Branch 4)
3. keyring_path = "m/44'/999'/0'/4'/0'/"
   keyring_secret = SLIP0010_Derive(master_seed, keyring_path)

// Step 4: Create encrypted Keybox
4. keybox_payload = CBOR_encode({
       graph_key_secret: keyring_secret,
       derivation_path: derivation_path
   })

   keybox = Lockbox_Create(
       recipient_public: device_encryption_key.public_key,
       secret_to_lock: keyring_secret,
       rng: rng
   )

// Step 5: Create authorization block
5. auth_block = {
       type: "authorization",
       device_pub_key: device_signing_key.public_key,
       device_encryption_key: device_encryption_key.public_key,
       derivation_path: derivation_path,
       keybox: keybox,
       label: new_device_info.label,  // e.g., "MacBook Pro 2024"
       authorized_at: unix_timestamp()
   }

// Step 6: Sign with Legislator key
6. block_cid = CID(0x57, SHA2-256(DAG-CBOR(auth_block)))
7. signature = legislator_signer.sign(block_cid)
8. auth_block.signature = signature

// Step 7: Add to Identity Graph
9. Add auth_block to /credentials/<device_pub_key_hex>
10. Create new identity manifest with updated graph

11. Return auth_block.cid, nil
```

---

## 5. Ritual of Revocation (Compromise Recovery)

Revocation terminates the authority of a compromised or lost credential.

### 5.1. Revocation Algorithm

```
Input:  legislator_signer, compromised_pub_key, reason
Output: revocation_block_cid, error (optional)

// Step 1: Create revocation block
1. revocation_block = {
       type: "revocation",
       target_public_key: compromised_pub_key,
       reason: reason,  // "device_lost", "compromised", "retired"
       revoked_at: unix_timestamp()
   }

// Step 2: Sign with Legislator key
2. block_cid = CID(0x57, SHA2-256(DAG-CBOR(revocation_block)))
3. signature = legislator_signer.sign(block_cid)
4. revocation_block.signature = signature

// Step 3: Add to Identity Graph
5. Add revocation_block to /revocations/<compromised_pub_key_hex>
6. Create new identity manifest with updated graph

// Step 4: Rotate Keyring Secret (forward secrecy)
7. Increment keyring_version
8. Derive new keyring_secret from Branch 4
9. Re-encrypt all graph keys with new keyring_secret
10. Update Identity Graph with new keyring

11. Return revocation_block.cid, nil
```

---

## 6. Ritual of Correction (Timeline Force-Push)

Timeline Correction is the procedure for erasing the history created by an unauthorized actor before their credential was revoked.

### 6.1. Correction Algorithm

```
Input:  legislator_signer, last_good_anchor_cid, malicious_branch_heads
Output: correction_manifest_cid, error (optional)

// Step 1: Verify last_good_anchor is valid
1. anchor_manifest = store.get_manifest(last_good_anchor_cid)
   if anchor_manifest is null:
       return null, "Last good anchor not found"

// Step 2: Create correction manifest
2. correction_header = {
       graph_id: identity_graph_id,
       content_root: anchor_manifest.header.content_root,
       parents: [last_good_anchor_cid],  // Only good parent
       identity_anchor: last_good_anchor_cid,
       created_at: unix_timestamp()
   }

// Step 3: Sign with Legislator key
3. correction_cid = CID(0x58, SHA2-256(DAG-CBOR(correction_header)))
4. signature = legislator_signer.sign(correction_cid)

5. correction_manifest = {
       header: correction_header,
       author: legislator_signer.public_key(),
       signature: signature
   }

// Step 4: Broadcast correction
6. Publish correction_manifest to Relay
7. Peers will see two branches:
   - Correction branch (signed by Legislator)
   - Malicious branch (signed by compromised Executive)

// Step 5: Deterministic resolution
8. Peers apply "Legislator precedence" rule:
   - Legislator-signed branch always wins
   - Malicious branch becomes "dead fork"

9. Return correction_manifest.cid, nil
```

---

## 7. Ritual of State Restoration (Full Recovery)

State Restoration is the reconstruction of an identity on new hardware after total device loss.

### 7.1. Recovery Algorithm

```
Input:  mnemonic (24 words), passphrase (optional), relay
Output: identity_restored (bool), error (optional)

// Step 1: Derive master seed
1. seed = PBKDF2-HMAC-SHA512(
       password = normalize(mnemonic),
       salt = "mnemonic" + passphrase,
       iterations = 2048
   )

// Step 2: Derive Legislator key
2. legislator_path = "m/44'/999'/0'/0'/"
   legislator_key = SLIP0010_Derive(seed, legislator_path)

// Step 3: Derive Discovery ID
3. discovery_id = HMAC-SHA256(
       key: seed,
       message: "akshara.v1.discovery"
   )

// Step 4: Find Identity Graph on Relay
4. identity_heads = relay.query_by_discovery_id(discovery_id)
   if identity_heads is empty:
       return false, "No identity graph found"

// Step 5: Resolve latest identity manifest
5. latest_manifest = resolve_latest_manifest(identity_heads)

// Step 6: Verify identity integrity
6. valid = verify_identity_graph(latest_manifest, legislator_key)
   if not valid:
       return false, "Identity verification failed"

// Step 7: Restore Keyring Secret
7. keyring_path = "m/44'/999'/0'/4'/0'/"
   keyring_secret = SLIP0010_Derive(seed, keyring_path)

// Step 8: Decrypt graph keys
8. graph_keys = decrypt_all_graph_keys(
       identity_graph: latest_manifest,
       keyring_secret: keyring_secret
   )

// Step 9: Authorize new device
9. new_device_cid = authorize_new_device(
       legislator_key: legislator_key,
       master_seed: seed,
       label: "New Device " + unix_timestamp()
   )

10. Return true, nil
```

---

## 8. Test Vectors

### Test Vector 1: Genesis from Known Mnemonic

```
Input:
  Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
  Passphrase: ""

Expected:
  Seed: bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8
  Legislator Path: m/44'/999'/0'/0'/
  Genesis Manifest: CID 0x58... (computed from header)
```

### Test Vector 2: Authorization Round-Trip

```
Setup:
  Existing identity with Legislator key
  New device wants to join

Process:
  1. Generate device keypair
  2. Create authorization block
  3. Sign with Legislator key
  4. Add to /credentials/<device_pubkey>
  5. Create new identity manifest

Expected Result:
  Device can now sign manifests on behalf of identity
```

### Test Vector 3: Revocation + Key Rotation

```
Setup:
  Identity with 3 authorized devices
  Device 2 is compromised

Process:
  1. Create revocation block for Device 2
  2. Sign with Legislator key
  3. Add to /revocations/<device2_pubkey>
  4. Rotate Keyring Secret (increment version)
  5. Re-encrypt all graph keys

Expected Result:
  Device 2 can no longer sign
  Device 2 can no longer decrypt graph keys
  Devices 1 and 3 continue working
```

### Test Vector 4: Full Recovery

```
Input:
  Mnemonic: (24 words from Test Vector 1)
  Passphrase: ""

Process:
  1. Derive seed from mnemonic
  2. Derive Discovery ID
  3. Query Relay for identity graph
  4. Verify identity graph integrity
  5. Derive Keyring Secret
  6. Decrypt graph keys
  7. Authorize new device

Expected Result:
  Full identity restored
  All graph keys recovered
  New device authorized
```

---

## 9. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Device theft** | Revocation invalidates device's authority |
| **Key compromise** | Keyring rotation prevents decryption of future data |
| **Timeline corruption** | Correction ritual prunes malicious history |
| **Total device loss** | 24-word recovery restores everything |

### Assumptions

1. **Mnemonic security:** 24 words are stored securely
2. **Legislator key security:** Used only for authorization/revocation
3. **Relay availability:** Identity graph is accessible on Relay

### Limitations

| Limitation | Impact |
|------------|--------|
| **Mnemonic loss** | Identity permanently unrecoverable |
| **Revocation delay** | Window between compromise and revocation propagation |
| **Correction is destructive** | Malicious branch history is lost (but remains in DAG) |

### Critical Security Properties

| Property | Guarantee |
|----------|-----------|
| **Forward Secrecy** | Revoked devices can't decrypt future data (keyring rotation) |
| **Legislator Precedence** | Legislator-signed branches always win over Executive-signed branches |
| **Deterministic Recovery** | Same 24 words → same identity, every time |

---

## 10. References

- [Key Derivation Specification](derivation.md)
- [Authority Verification Specification](authority.md)
- [Graph Snapshots Specification](../graph-model/snapshots.md)
