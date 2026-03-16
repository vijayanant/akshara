---
title: "Identity and Authority Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-03-14
---

# Identity and Authority Specification

## 1. Motivation

### The Problem

Most collaboration systems have a fundamental weakness: **identity is a single key**.

- Lose your device → lose your identity (fragile)
- Backup your key → risk compromise (insecure)
- Revoke access → centralized server required (vendor lock-in)

This creates an impossible choice between security and usability.

### The Akshara Solution

Akshara uses **tiered identity** with hierarchical key derivation:

```
24-word mnemonic (Tier 1: Master)
    │
    └─→ Identity Graph (Tier 2: Timeline of Authority)
           │
           ├─→ Branch 0: Legislator (authorize/revoke devices)
           ├─→ Branch 1: Executive (sign manifests daily)
           ├─→ Branch 2: Secret (encrypt graph content)
           ├─→ Branch 3: Handshake (pre-keys for sharing)
           ├─→ Branch 4: Keyring (cross-device key sync)
           └─→ Branch 5: Discovery (anonymous graph discovery)
```

**Benefits:**
- **Recoverable:** 24 words restore everything
- **Revocable:** Lost device? Revoke that branch only
- **Isolated:** Compromised device can't derive other branches
- **Portable:** No server needed for recovery

### Design Rationale

For the full design decisions, see:
- [Tiered Identity Model](../../docs_blueprint/identity/tiered-model.md)
- [BIP-39 Technical Deep-Dive](../../docs_blueprint/identity/bip-technical-deepdive.md)
- [Identity Graph](../../docs_blueprint/identity/identity-graph.md)

---

## 2. Overview

This specification defines the Akshara Identity protocol for managing cryptographic authority and key derivation in an asynchronous, multi-device setting.

The protocol provides a hierarchical root of trust for content-addressed Merkle-DAGs. It enables:
- **Deterministic recovery** of state from a 24-word mnemonic
- **Verifiable revocation** of compromised credentials
- **No centralized registry** or trusted third party

### Key Concepts

| Term | Meaning |
|------|---------|
| **Master Identity** | 24-word BIP-39 mnemonic, the root of all trust |
| **Identity Graph** | Append-only graph of authorizations and revocations |
| **Legislator Key** | Branch 0: authorizes/revokes devices |
| **Executive Key** | Branch 1: signs manifests for daily use |
| **Discovery ID** | HMAC-derived identifier for finding identity graphs |
| **GraphKey** | Symmetric key for encrypting a specific graph |

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  Tier 1: Master Root (24 words)                     │
│  - Never touches network                            │
│  - Used only for recovery                           │
└─────────────────────────────────────────────────────┘
                    │
                    ▼ (SLIP-0010 derivation)
┌─────────────────────────────────────────────────────┐
│  Tier 2: Identity Graph                             │
│  - /credentials/<pubkey>  - Authorized devices      │
│  - /revocations/<pubkey>  - Revoked devices         │
│  - /capabilities/<pubkey> - Scoped permissions      │
└─────────────────────────────────────────────────────┘
                    │
                    ▼ (Delegation)
┌─────────────────────────────────────────────────────┐
│  Tier 3: Functional Branches                        │
│  - Branch 0: Legislator (manage identity)           │
│  - Branch 1: Executive (sign manifests)             │
│  - Branch 2: Secret (encrypt content)               │
│  - Branch 3: Handshake (share asynchronously)       │
│  - Branch 4: Keyring (cross-device key sync)        │
│  - Branch 5: Discovery (anonymous discovery)        │
└─────────────────────────────────────────────────────┘
```

---

## 3. Specification Structure

| Document | Purpose |
|----------|---------|
| [**Key Derivation**](derivation.md) | BIP-39, SLIP-0010, derivation paths, test vectors |
| [**Authority Verification**](authority.md) | Causal walk algorithm, revocation checks |
| [**Credential Lifecycle**](lifecycle.md) | Authorization, revocation, recovery rituals |
| [**Resource Indexing**](discovery.md) | Discovery IDs, graph key derivation |

---

## 4. Core Properties

| Property | Description |
|----------|-------------|
| **Hierarchical Isolation** | Compromise of Branch 1 key cannot derive Branch 0 or Master |
| **Causal Authority** | Signatures verified against Identity Graph at anchor point |
| **Stateless Recovery** | All keys recoverable from 24 words + GraphID |

---

## 5. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Device theft** | Revoke that device's key; others remain valid |
| **Key compromise** | Hardened derivation prevents parent/ sibling key derivation |
| **Lost seed** | Social recovery (future extension) |
| **Relay attack** | Identity Graph signed by Legislator; verified by SDK |

### Limitations

| Limitation | Impact |
|------------|--------|
| **24-word loss** | Identity permanently unrecoverable |
| **Device compromise (before revocation)** | Attacker can sign until revocation propagates |
| **Relay withholding revocation** | Temporary window; mitigated by multi-relay fetch |

### Assumptions

1. **Honest-but-curious Relay:** Relays deliver messages correctly but may try to learn metadata
2. **Secure randomness:** Implementations have access to cryptographically secure RNG
3. **Bounded compromise:** At most N-1 of N authorized devices are compromised at once

---

## 6. Test Vectors

See [Key Derivation Specification](derivation.md#test-vectors) for concrete test vectors.

---

## 7. References

- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [SLIP-0010: Universal private key derivation from master private key](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [Akshara Vision](../VISION.md)
