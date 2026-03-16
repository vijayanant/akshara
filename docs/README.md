# Akshara Documentation

**Version:** 0.1.0-alpha.2
**Status:** Accepted

---

## What Is Akshara?

Akshara (ಅಕ್ಷರ, "The Imperishable") is a protocol for **encrypted, offline-first collaboration** where the hosting infrastructure cannot read or modify your data.

### Core Ideas

1. **Everything Is a Graph**
   All data is organized as Merkle-DAGs (Directed Acyclic Graphs). This enables:
   - Offline edits (no server required)
   - Mathematical conflict resolution (no merge conflicts)
   - Tamper-evident history (any modification changes the CID)

2. **Blind Infrastructure**
   Relays host encrypted blobs without being able to read them. This means:
   - Hosting is a commodity (any provider works)
   - Relays can't be subpoenaed for user data
   - You can self-host or use SaaS interchangeably

3. **24-Word Recovery**
   Full identity recovery from a single BIP-39 mnemonic phrase:
   - No "forgot password" emails
   - No centralized account recovery
   - No vendor lock-in

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  L0: The Core (Pure Math)                                   │
│  - Content-addressed graphs (DAG-CBOR)                      │
│  - Cryptographic identity (BIP-39, SLIP-0010)               │
│  - Zero side effects (no I/O, no network, no filesystem)    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  L1: The SDK (The Brain)                                    │
│  - Governance auditing (who can sign what)                  │
│  - Encryption/decryption (XChaCha20-Poly1305)               │
│  - Synchronization (symmetric reconciliation)               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  L2: The Relay (The Pipe)                                   │
│  - Hosts encrypted blobs                                    │
│  - Routes manifests                                         │
│  - Cannot read content (blind)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Normative Roadmap & Gaps

The following protocol areas are planned but not yet normatively defined in the `specs/` directory.

| Component | Description | Status |
|-----------|-------------|--------|
| **Succession Rituals** | Formal logic for permanent ownership transfer | **Planned (v0.2)** |
| **Capabilities Spec** | Fine-grained path-level permission schemas | **Planned (v0.2)** |
| **Social Recovery** | M-of-N shard-based identity restoration | **Planned (v0.3)** |
| **Garbage Collection** | Reachability-based pruning and space reclamation | **Planned (v0.3)** |
| **Interactive Nirūpana** | Multi-turn sync for deep encrypted indices | **Research** |

## How to Read This Documentation

### I'm New to Akshara

Start here:
1. **[Vision](vision/)** — Philosophy, design decisions, "why"
2. **[Getting Started Guide](guides/)** — Create identity, make a graph, sync
3. **[Identity Spec](specs/identity/)** — How tiered identity works

**You don't need to read the spec** unless you're building an implementation.

---

### I'm Building an Implementation

Read the specifications. Each spec includes:
- **Motivation** — Why this exists
- **Algorithms** — What to implement (pseudocode)
- **Test Vectors** — How to verify your implementation
- **Security Considerations** — Threat model, limitations

| Specification | Status | Description |
|---------------|--------|-------------|
| [Identity](specs/identity/) | Draft | Key derivation, authority verification, revocation |
| [Graph Model](specs/graph-model/) | Draft | Blocks, manifests, CIDs, indices |
| [Synchronization](specs/synchronization/) | Draft | Reconciliation, fulfillment |
| [Sharing](specs/sharing/) | Draft | Lockboxes, pre-keys, async handshakes |
| [Storage](specs/storage/) | Draft | GraphStore interface, semantics |

---

### I'm Using the Rust Implementation

See the crate READMEs:
- **[akshara-aadhaara](../aadhaara/README.md)** — Core library usage
- **[akshara-sdk](../sdk/)** — (Coming soon)
- **[akshara-relay](../relay/)** — (Coming soon)

---

## Document Types

| Type | Location | Purpose |
|------|----------|---------|
| **Vision** | [`vision/`](vision/) | Philosophy, design rationale, "why" |
| **Specification** | [`specs/`](specs/) | Normative requirements for implementers |
| **Guides** | [`guides/`](guides/) | Tutorials, how-tos, examples |
| **API Reference** | [`api/`](api/) | Rust API documentation (rustdoc) |

---

## Versioning

This is **v0.1.0-alpha**. Expect changes.

- **Draft** specs may have incomplete sections
- **Test vectors** are being added progressively
- **Security considerations** are being documented

For the latest, check the git repository.

---

## Contributing

Found an error? Have a question?

1. Open an issue on GitHub
2. Check existing discussions in the blueprint repo
3. Join the conversation (link TBD)

---

## Quick Reference

| Term | Meaning |
|------|---------|
| **Akshara** | "The Imperishable" (Kannada). The protocol name. |
| **Aadhaara** | "Foundation" (Kannada). The core Rust crate. |
| **CID** | Content Identifier. Cryptographic hash of data. |
| **DAG-CBOR** | Canonical CBOR encoding for Merkle-DAGs. |
| **GraphKey** | Symmetric key for encrypting a graph's content. |
| **Identity Graph** | Append-only graph of authorizations/revocations. |
| **Lakshana** | "Defining mark" (Sanskrit). Content-addressed identifier. |
| **Lockbox** | Encrypted envelope for sharing GraphKeys. |
| **Manifest** | Signed snapshot of a graph's state. |
| **Satyātā** | "Truth" (Sanskrit). Sync protocol grammar. |

---

**Last Updated:** 2026-03-14
