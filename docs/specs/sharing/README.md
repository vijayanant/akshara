---
title: "Sharing Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Sharing Specification

## 1. Motivation

### The Problem

How do you give someone access to an encrypted graph?

- **Can't send key plaintext:** Network can read it
- **Can't pre-share keys:** Users don't know each other in advance
- **Must work asynchronously:** Recipient might be offline
- **Must be deniable:** Relay shouldn't know who shared with whom

### The Akshara Solution

**Two-layer sharing:**

```
Layer 1: Lockboxes
  - Encrypt GraphKey with recipient's public key
  - Only recipient can decrypt
  - Forward secret (ephemeral keys)

Layer 2: Pre-Keys
  - One-time keys for async handshake
  - Recipient doesn't need to be online
  - Relay can't link sender to recipient
```

---

## 2. Overview

This specification defines the protocols for securely sharing encrypted graphs with other users in a decentralized, asynchronous manner.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Lockbox** | Encrypted envelope containing a GraphKey |
| **Pre-Key** | One-time-use key for async handshake |
| **Pre-Key Bundle** | Collection of pre-keys signed by identity |
| **GraphKey** | Symmetric key for encrypting graph content |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Sharing Flow                                               │
│                                                             │
│  Alice (wants to share with Bob)                            │
│       │                                                     │
│       ↓                                                     │
│  1. Fetch Bob's Pre-Key Bundle from Relay                   │
│       │                                                     │
│       ↓                                                     │
│  2. Verify bundle signature                                 │
│       │                                                     │
│       ↓                                                     │
│  3. Pick one pre-key                                        │
│       │                                                     │
│       ↓                                                     │
│  4. Create Lockbox (encrypt GraphKey)                       │
│       │                                                     │
│       ↓                                                     │
│  5. Upload Lockbox to Bob's inbox                           │
│       │                                                     │
│       ↓                                                     │
│  Bob (wakes up)                                             │
│       │                                                     │
│       ↓                                                     │
│  6. Download Lockbox from inbox                             │
│       │                                                     │
│       ↓                                                     │
│  7. Re-derive pre-key private key                           │
│       │                                                     │
│       ↓                                                     │
│  8. Open Lockbox → recover GraphKey                         │
│       │                                                     │
│       ↓                                                     │
│  9. Sync graph with new access                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Specification Structure

| Document | Purpose |
|----------|---------|
| [**Lockboxes**](lockboxes.md) | Pairwise asymmetric enveloping |
| [**Pre-Keys**](prekeys.md) | Asynchronous handshakes |

---

## 4. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Eavesdropping** | X25519 ECDH + XChaCha20-Poly1305 |
| **Replay attacks** | Nonce + associated data binding |
| **Relay tampering** | Bundle signatures |
| **Key compromise** | Forward secrecy (ephemeral keys purged) |

### Assumptions

1. **Pre-key availability:** Recipient maintains pre-key bundle
2. **Bundle freshness:** Recipient replenishes bundle before exhaustion
3. **Honest relay:** Relay atomically consumes pre-keys

---

## 5. References

- [Key Derivation Specification](../identity/derivation.md)
- [Graph Model Specification](../graph-model/README.md)
