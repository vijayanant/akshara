---
title: "Lockbox Specification"
subtitle: "Pairwise Asymmetric Enveloping in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Lockbox Specification

## 1. Motivation

### The Problem

How do you share a symmetric key (`GraphKey`) with someone over an untrusted network?

- **Can't send plaintext:** Network can read it
- **Can't pre-share keys:** Users don't know each other in advance
- **Can't use central KMS:** No centralized infrastructure
- **Must work asynchronously:** Recipient might be offline

### The Akshara Solution

**Lockboxes** — hybrid encryption envelopes:

```
Sender (Alice):
  1. Generate ephemeral X25519 keypair
  2. ECDH with recipient's public key → shared secret
  3. Encrypt GraphKey with shared secret
  4. Send: {ephemeral_pubkey, ciphertext}

Recipient (Bob):
  1. ECDH with own private key + sender's ephemeral pubkey → same shared secret
  2. Decrypt ciphertext → GraphKey
```

**Key properties:**
- **Pairwise:** Each lockbox is unique to sender-recipient pair
- **Forward secret:** Ephemeral keys are purged after use
- **Asynchronous:** Recipient doesn't need to be online

### Design Rationale

For the full design decisions, see:
- [Asynchronous Sharing: The Pre-Key Registry](../../docs_blueprint/identity/asynchronous-registry.md)

---

## 2. Overview

A **Lockbox** is the atomic unit of access transport in Akshara. It allows an authorized credential to securely send a symmetric `GraphKey` to a new recipient over an untrusted network.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Lockbox** | Encrypted envelope containing a GraphKey |
| **Ephemeral Key** | One-time X25519 keypair for handshake |
| **Shared Secret** | ECDH result used to derive encryption key |
| **Handshake Key** | 256-bit key derived from shared secret |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Lockbox Structure                                          │
│                                                             │
│  {                                                          │
│    "ephemeral_pk": X25519_public_key,  // For ECDH         │
│    "nonce": 24_bytes,                  // XChaCha20 nonce   │
│    "ciphertext": encrypted_payload,    // GraphKey + meta   │
│    "tag": 16_bytes                     // Auth tag          │
│  }                                                          │
│                                                             │
│  Payload (decrypted):                                       │
│  {                                                          │
│    "graph_id": UUID,                                        │
│    "graph_key": 32_bytes,                                   │
│    "iteration": u64                                         │
│  }                                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Handshake

Lockboxes use **X25519** (Diffie-Hellman) key agreement to establish a shared secret between sender and recipient.

### 3.1. Sender Side (Creation)

```
Input:  recipient_public_key (X25519), graph_key, graph_id, iteration, rng
Output: lockbox

1. // Generate ephemeral keypair
   ephemeral_sk, ephemeral_pk = X25519_keypair(rng)

2. // ECDH to derive shared secret
   shared_secret = X25519_DH(ephemeral_sk, recipient_public_key)

3. // KDF to derive handshake key
   handshake_key = HKDF-SHA256(
       salt = "akshara.v1.lockbox",
       ikm = shared_secret,
       info = "lockbox_encryption_key",
       length = 32
   )

4. // Generate nonce
   nonce = random_24_bytes(rng)

5. // Encrypt payload
   plaintext = CBOR_encode({
       graph_id: graph_id,
       graph_key: graph_key,
       iteration: iteration
   })
   ciphertext, tag = XChaCha20-Poly1305_Encrypt(
       key = handshake_key,
       nonce = nonce,
       plaintext = plaintext,
       associated_data = recipient_public_key  // Bind to recipient
   )

6. // Build lockbox
   lockbox = {
       ephemeral_pk: ephemeral_pk,
       nonce: nonce,
       ciphertext: ciphertext,
       tag: tag
   }

7. Return lockbox
```

### 3.2. Recipient Side (Extraction)

```
Input:  lockbox, recipient_private_key (X25519)
Output: graph_key, graph_id, iteration, error (optional)

1. // ECDH to derive same shared secret
   shared_secret = X25519_DH(recipient_private_key, lockbox.ephemeral_pk)

2. // KDF to derive same handshake key
   handshake_key = HKDF-SHA256(
       salt = "akshara.v1.lockbox",
       ikm = shared_secret,
       info = "lockbox_encryption_key",
       length = 32
   )

3. // Decrypt payload
   plaintext = XChaCha20-Poly1305_Decrypt(
       key = handshake_key,
       nonce = lockbox.nonce,
       ciphertext = lockbox.ciphertext || lockbox.tag,
       associated_data = recipient_public_key  // Must match sender's AD
   )
   if decryption fails:
       return null, "Authentication failed"

4. // Parse payload
   payload = CBOR_decode(plaintext)

5. Return payload.graph_key, payload.graph_id, payload.iteration, nil
```

---

## 4. Lockbox Structure

A Lockbox is encoded in **Canonical DAG-CBOR** and consists of:

```cbor
{
  "ephemeral_pk": <32-byte X25519 public key>,
  "nonce": <24-byte nonce>,
  "ciphertext": <encrypted bytes>,
  "tag": <16-byte authentication tag>
}
```

### Field Descriptions

| Field | Size | Purpose |
|-------|------|---------|
| `ephemeral_pk` | 32 bytes | Sender's one-time X25519 public key |
| `nonce` | 24 bytes | XChaCha20 nonce (random) |
| `ciphertext` | variable | Encrypted payload (GraphKey + metadata) |
| `tag` | 16 bytes | Poly1305 authentication tag |

### Payload Schema (Decrypted)

```cbor
{
  "graph_id": <16-byte UUID>,
  "graph_key": <32-byte symmetric key>,
  "iteration": <u64>  // Key version (for rekeying)
}
```

---

## 5. Algorithms

### 5.1. Creating a Lockbox for Sharing

```
Input:  recipient_lakshana, graph_id, graph_key, rng
Output: lockbox_block (to be added to Relay)

1. // Create lockbox
   lockbox = create_lockbox(recipient_pubkey, graph_key, graph_id, iteration=0, rng)

2. // THE BLIND MANDATE: Lockboxes MUST be delivered via Lakshanas
// The Relay sees an envelope moving to an opaque Lakshana. 
// The 'author' of the block MUST be anonymous (all zeros or a one-time key).

3. // Create block
   block = Block(
       content: lockbox,
       type: "lockbox",
       parents: [],
       author: 0x00...00  // Anonymous author
   )

4. // Push to Relay inbox
   relay.push_inbox(recipient_lakshana, block)
```

### 5.2. Processing Received Lockboxes

```
Input:  lockbox_block, recipient_identity, store
Output: (graph_id, graph_key) or error

1. // Decrypt block content
   lockbox = decrypt_lockbox_content(lockbox_block.content, recipient_identity.graph_key)

2. // Extract GraphKey
   graph_key, graph_id, iteration = open_lockbox(lockbox, recipient_identity.encryption_key)
   if error:
       return error

3. // Store in resource index
   store.add_graph_key(graph_id, graph_key, iteration)

4. Return graph_id, graph_key
```

---

## 6. Test Vectors

### Test Vector 1: Basic Lockbox Creation

| Field | Value |
|-------|-------|
| **Recipient Public Key** | `X25519:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| **Graph ID** | `550e8400-e29b-41d4-a716-446655440000` |
| **Graph Key** | `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| **Iteration** | `0` |
| **Ephemeral Key** | (generated by RNG) |
| **Nonce** | (generated by RNG) |

### Test Vector 2: Lockbox Round-Trip

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Alice creates lockbox for Bob | Lockbox with ephemeral_pk, ciphertext, tag |
| 2 | Bob opens lockbox with his private key | graph_id, graph_key extracted |
| 3 | Verify extracted key matches original | `extracted_key == original_key` |

---

## 7. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Eavesdropping** | X25519 ECDH ensures only recipient can derive shared secret |
| **Replay attacks** | Associated data binds lockbox to recipient's public key |
| **Key leakage** | Ephemeral keys purged after use (forward secrecy) |
| **Tampering** | Poly1305 authentication tag detects modification |

### Security Invariants

| Invariant | Requirement |
|-----------|-------------|
| **Pairwise Isolation** | Every lockbox MUST be unique to sender-recipient pair |
| **Authenticated Delivery** | Recipient MUST verify tag before using graph_key |
| **Ephemeral Purge** | Sender MUST purge ephemeral secret key after creation |

### Assumptions

1. **Secure RNG:** Ephemeral keys are cryptographically random
2. **Recipient key security:** Recipient's encryption key is not compromised
3. **Associated data binding:** AD prevents lockbox replay to different recipient

### Limitations

| Limitation | Impact |
|------------|--------|
| **Recipient key compromise** | Attacker can open all lockboxes addressed to recipient |
| **No sender authentication** | Lockbox doesn't prove who sent it (only that they know recipient's pubkey) |
| **Key rotation required** | If GraphKey is compromised, must rekey entire graph |

---

## 8. References

- [X25519 (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748)
- [XChaCha20-Poly1305 (RFC 8439)](https://datatracker.ietf.org/doc/html/rfc8439)
- [HKDF (RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869)
- [Pre-Key Specification](prekeys.md)
