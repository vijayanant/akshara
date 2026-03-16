---
title: "Pre-Key Specification"
subtitle: "Asynchronous Handshakes and Offline Sharing"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Pre-Key Specification

## 1. Motivation

### The Problem

Lockboxes require the recipient's public key. But what if:

- **Recipient is offline?** Can't negotiate handshake
- **No pre-shared keys?** First-time contact
- **No central directory?** Decentralized system

Traditional solutions:
- **Both parties online:** Signal protocol (requires simultaneous presence)
- **Central server:** Keybase (trusts server to not modify keys)
- **Out-of-band exchange:** QR codes, in-person (poor UX)

### The Akshara Solution

**Pre-Keys** — signed, one-time-use keys for asynchronous handshakes:

```
Alice (offline):
  1. Generate 100 one-time X25519 keys
  2. Sign them with Executive key
  3. Upload to Relay as "Pre-Key Bundle"

Bob (wants to share with Alice):
  1. Fetch Alice's bundle from Relay
  2. Verify bundle signature
  3. Pick one pre-key
  4. Create lockbox
  5. Upload to Alice's inbox

Alice (wakes up):
  1. Download lockbox from inbox
  2. See which pre-key was used
  3. Re-derive private key from seed
  4. Open lockbox
```

**Key properties:**
- **Asynchronous:** Recipient doesn't need to be online
- **Forward secret:** Used pre-keys are purged
- **Verifiable:** Bundle signed by identity
- **One-time:** Each pre-key used once

### Design Rationale

For the full design decisions, see:
- [Asynchronous Sharing: The Pre-Key Registry](../../docs_blueprint/identity/asynchronous-registry.md)

---

## 2. Overview

The Pre-Key protocol enables **Asynchronous Sharing**, allowing an authorized credential to delegate access to a recipient who is currently offline. It removes the requirement for both parties to be simultaneously present on the network to perform a cryptographic handshake.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Pre-Key** | One-time-use X25519 key for async handshake |
| **Pre-Key Bundle** | Collection of pre-keys signed by identity |
| **Static Identity Key** | Long-term X25519 key for identity |
| **Depletion** | Bundle running low on unused pre-keys |
| **Replenishment** | Generating new pre-keys and uploading |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Pre-Key Bundle Structure                                   │
│                                                             │
│  {                                                          │
│    "static_identity_key": X25519_public_key,                │
│    "pre_keys": [                                            │
│      { "index": 0, "public_key": X25519_pubkey_0 },         │
│      { "index": 1, "public_key": X25519_pubkey_1 },         │
│      ...                                                    │
│      { "index": 99, "public_key": X25519_pubkey_99 }        │
│    ],                                                       │
│    "signature": Executive_Key_Signature,                    │
│    "credential_index": 0,                                   │
│    "next_prekey_index": 100                                 │
│  }                                                          │
│                                                             │
│  Stored on Relay as:                                        │
│    /inbox/<identity_id>/prekeys                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Pre-Key Derivation

Pre-Keys are derived from **Branch 3** (Handshake Branch) of the identity tree.

### 3.1. Derivation Path

```
m / 44' / 999' / 0' / 3' / <credential_index>' / <prekey_index>' /

Where:
  - 44'        : BIP-44 purpose
  - 999'       : Akshara coin type
  - 0'         : Primary identity account
  - 3'         : Branch 3 (Handshake)
  - credential_index' : Which device credential
  - prekey_index'     : Which pre-key (0, 1, 2, ...)
```

### 3.2. Pre-Key Generation Algorithm

```
Input:  master_seed, credential_index, prekey_start_index, count
Output: Array of (index, public_key) pairs

1. pre_keys = []

2. for i from prekey_start_index to prekey_start_index + count - 1:
       // Derive path
       path = "m/44'/999'/0'/3'/" + credential_index + "'/" + i + "'/"

       // Derive key
       signing_key = SLIP0010_Derive(master_seed, path)
       x25519_key = Ed25519_to_X25519(signing_key)

       pre_keys.push({
           index: i,
           public_key: x25519_key.public_key()
       })

3. Return pre_keys
```

### 3.3. Bundle Signing

```
Input:  pre_keys, static_identity_key, executive_signer
Output: signed_bundle

1. bundle = {
       static_identity_key: static_identity_key,
       pre_keys: pre_keys,
       credential_index: executive_signer.credential_index(),
       next_prekey_index: pre_keys[-1].index + 1
   }

2. // Sign the bundle
   message = CBOR_encode(bundle)
   signature = executive_signer.sign(message)

3. signed_bundle = {
       bundle: bundle,
       signature: signature
   }

4. Return signed_bundle
```

---

## 4. Asynchronous Handshake Protocol

### 4.1. Initiator Side (Bob)

```
Input:  recipient_identity_id, graph_id, graph_key, rng, relay
Output: lockbox_uploaded (bool), error (optional)

// Step 1: Fetch pre-key bundle
1. bundle = relay.get_prekey_bundle(recipient_identity_id)
   if bundle is null:
       return false, "No pre-key bundle available"

// Step 2: Verify bundle signature
2. valid = verify_bundle_signature(bundle)
   if not valid:
       return false, "Invalid bundle signature"

// Step 3: Select pre-key
3. if len(bundle.pre_keys) == 0:
       return false, "Pre-key bundle exhausted"

   selected = bundle.pre_keys[0]  // Pick first available

// Step 4: Perform ECDH handshake
4. ephemeral_sk, ephemeral_pk = X25519_keypair(rng)
   shared_secret = X25519_DH(ephemeral_sk, selected.public_key)
   handshake_key = HKDF-SHA256(shared_secret, salt="akshara.v1.lockbox")

// Step 5: Create lockbox
5. nonce = random_12_bytes(rng)
   plaintext = CBOR_encode({graph_id, graph_key, iteration: 0})
   ciphertext, tag = XChaCha20-Poly1305_Encrypt(
       handshake_key, nonce, plaintext,
       associated_data: bundle.static_identity_key
   )

   lockbox = {
       ephemeral_pk: ephemeral_pk,
       nonce: nonce,
       ciphertext: ciphertext,
       tag: tag,
       used_prekey_index: selected.index
   }

// Step 6: Upload to recipient's inbox
6. relay.upload_lockbox(recipient_identity_id, lockbox)

// Step 7: Mark pre-key as consumed (optimistic)
7. relay.consume_prekey(recipient_identity_id, selected.index)

8. Return true, nil
```

### 4.2. Recipient Side (Alice)

```
Input:  lockbox, master_seed, credential_index, encryption_key
Output: graph_id, graph_key, error (optional)

// Step 1: Extract pre-key index
1. prekey_index = lockbox.used_prekey_index

// Step 2: Re-derive pre-key private key
2. path = "m/44'/999'/0'/3'/" + credential_index + "'/" + prekey_index + "'/"
   signing_key = SLIP0010_Derive(master_seed, path)
   x25519_sk = Ed25519_to_X25519(signing_key)

// Step 3: Perform ECDH
3. shared_secret = X25519_DH(x25519_sk, lockbox.ephemeral_pk)
   handshake_key = HKDF-SHA256(shared_secret, salt="akshara.v1.lockbox")

// Step 4: Decrypt lockbox
4. plaintext = XChaCha20-Poly1305_Decrypt(
       handshake_key, lockbox.nonce,
       lockbox.ciphertext || lockbox.tag,
       associated_data: static_identity_key
   )
   if error:
       return null, "Lockbox decryption failed"

// Step 5: Parse payload
5. payload = CBOR_decode(plaintext)

// Step 6: Purge pre-key (forward secrecy)
6. secure_delete(x25519_sk)

7. Return payload.graph_id, payload.graph_key, nil
```

---

## 5. Bundle Management

### 5.1. Depletion Detection

```
Input:  bundle
Output: needs_replenishment (bool)

THRESHOLD = 20  // Minimum pre-keys before replenishment

if len(bundle.pre_keys) < THRESHOLD:
    return true
else:
    return false
```

### 5.2. Replenishment Algorithm

```
Input:  master_seed, current_bundle, relay
Output: new_bundle_uploaded (bool), error (optional)

// Step 1: Generate new pre-keys
1. start_index = current_bundle.next_prekey_index
   new_pre_keys = derive_pre_keys(master_seed, current_bundle.credential_index, start_index, count=100)

// Step 2: Create new bundle
2. new_bundle = {
       static_identity_key: current_bundle.static_identity_key,
       pre_keys: new_pre_keys,
       credential_index: current_bundle.credential_index,
       next_prekey_index: start_index + 100
   }

// Step 3: Sign and upload
3. signed_bundle = sign_bundle(new_bundle, executive_signer)
   relay.upload_prekey_bundle(recipient_identity_id, signed_bundle)

4. Return true, nil
```

---

## 6. Security Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Forward Secrecy** | Once a pre-key's private key is used, it MUST be purged from memory |
| **One-Time Guarantee** | Relay MUST NOT vend the same pre-key to multiple initiators |
| **Bundle Integrity** | Bundle MUST be signed by Executive Key to prevent tampering |
| **Atomic Consumption** | Pre-key consumption MUST be atomic (fetch-and-remove) |

---

## 7. Test Vectors

### Test Vector 1: Pre-Key Derivation

```
Input:
  Mnemonic: "abandon abandon... art" (24 words)
  Passphrase: ""
  Credential Index: 0
  Pre-Key Index: 0

Expected:
  Derivation Path: m/44'/999'/0'/3'/0'/0'/
  Pre-Key Public Key: X25519: <derived pubkey>
```

### Test Vector 2: Async Handshake Round-Trip

```
Setup:
  Alice generates 100 pre-keys, uploads bundle to Relay
  Bob wants to share graph with Alice

Process:
  1. Bob fetches Alice's bundle from Relay
  2. Bob verifies bundle signature
  3. Bob picks pre-key index 0
  4. Bob creates lockbox, uploads to Alice's inbox
  5. Alice downloads lockbox
  6. Alice re-derives pre-key 0 private key
  7. Alice opens lockbox

Expected Result:
  Alice successfully extracts graph_id and graph_key
```

---

## 8. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Relay tampering** | Bundle signature prevents modification |
| **Pre-key replay** | One-time use; atomic consumption |
| **Device compromise** | Forward secrecy; used keys purged |
| **Eavesdropping** | X25519 ECDH ensures confidentiality |

### Assumptions

1. **Relay honesty:** Relay atomically consumes pre-keys
2. **Bundle availability:** Recipient replenishes bundle before exhaustion
3. **Secure derivation:** Master seed is secure

### Limitations

| Limitation | Impact |
|------------|--------|
| **Bundle exhaustion** | Sharing blocked until recipient replenishes |
| **Relay DoS** | Malicious relay can withhold bundles |
| **No sender authentication** | Lockbox doesn't prove who sent it |

---

## 9. References

- [Lockbox Specification](lockboxes.md)
- [Key Derivation Specification](../identity/derivation.md)
- [X25519 (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748)
