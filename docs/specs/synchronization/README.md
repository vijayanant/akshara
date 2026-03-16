---
title: "Synchronization Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Synchronization Specification

## 1. Motivation

### The Problem

Traditional sync protocols assume a **client-server model**:

- Client **requests** data from server
- Server **responds** with data
- Server is the **source of truth**

This breaks down for:
- **Offline-first apps:** No server available
- **P2P sync:** No central server exists
- **Blind infrastructure:** Relay can't read data to know what to send

### The Akshara Solution

**Symmetric Convergence** — both peers have gaps, both peers have knowledge to share:

```
Traditional:  Client ──request──> Server ──response──> Client
Akshara:      Peer A ←──surplus──> Peer B
              (both have what the other needs)
```

### The Satyātā Grammar

Akshara uses a philosophical framework from Sanskrit:

| Term | Meaning | Sync Role |
|------|---------|-----------|
| **Satyātā** (सत्यता) | "Truth-ness" | The state of truth (heads) |
| **Abhāva** (अभाव) | "Absence" | The gap (missing CIDs) |
| **Amsha** (अंश) | "Portion" | The data that fills the gap |
| **Nirūpana** (निरूपण) | "Determination" | The reconciliation algorithm |
| **Pradāna** (प्रदान) | "Provision" | The fulfillment algorithm |

**Why this matters:** We're not "requesting data from a server." We're **converging toward shared truth** as equals.

### Design Rationale

For the full design decisions, see:
- [The Knowledge Exchange: Unified DAG Reconciliation](../../docs_blueprint/synchronization/sync-protocol.md)
- [Causality, Time, and Conflict Resolution](../../docs_blueprint/synchronization/causality-and-time.md)

---

## 2. Overview

This specification defines the Akshara Synchronization protocol, which defines the mathematical and procedural rules for converging data across separate Merkle-DAG instances.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Heads (Satyātā)** | Set of manifest CIDs with no children (frontier) |
| **Known Set** | All CIDs reachable by walking backward from heads |
| **Surplus (Abhāva)** | CIDs one peer has that the other lacks |
| **Delta** | Expanded surplus (includes data blocks, not just manifests) |
| **Portion (Amsha)** | Single unit of data in transit |
| **Comparison** | Result of reconciliation (peer_surplus + self_surplus) |
| **Convergence Report** | Telemetry: manifests synced, blocks synced, bytes |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Sync Turn                                                 │
│                                                             │
│  1. Exchange Heads                                          │
│     Peer A: [head_a1, head_a2]                              │
│     Peer B: [head_b1]                                       │
│                                                             │
│  2. Reconciliation (Nirūpana)                               │
│     Peer A computes: "I'm missing X, Peer B is missing Y"   │
│                                                             │
│  3. Fulfillment (Pradāna)                                   │
│     Stream Portions for X and Y                             │
│                                                             │
│  4. Convergence Report                                      │
│     "Synced 15 manifests, 42 blocks, 128 KB"                │
└─────────────────────────────────────────────────────────────┘
```

### Sync Lifecycle

```
Phase I: Inbox Reconciliation (Blind Discovery)
  → Discover Lockboxes addressed to you
  → Extract GraphKeys and GraphIds

Phase II: Targeted Data Reconciliation
  → Sync specific graphs you now have access to
  → Converge on shared truth
```

---

## 3. Convergence Model

The protocol is designed to operate over a **"Blind Pipe"** transport, ensuring that the infrastructure facilitating the sync never gains access to the decrypted content or the social authority laws of the graph.

### Components

| Component | Specification |
|-----------|---------------|
| **Symmetric Reconciliation** | [Reconciliation](reconciliation.md) — LCA-based gap detection |
| **Blind Fulfillment** | [Fulfillment](fulfillment.md) — Portion transfer + telemetry |

---

## 4. Core Properties

| Property | Description |
|----------|-------------|
| **Location Independence** | Works SDK↔Relay or SDK↔SDK (P2P) |
| **Atomic Convergence** | All gaps identified in single exchange |
| **Functional Telemetry** | Every sync turn yields structured report |
| **Reverse Topological Ordering** | Heads delivered first (verify before ingest) |

---

## 5. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Blind relay attacks** | Content-addressed verification (CID check) |
| **Missing data injection** | CID verification before ingest |
| **DoS via head flooding** | Head limit (1024 max) |
| **Memory exhaustion** | Delta limit (100,000 addresses max) |

### Assumptions

1. **Content-addressed integrity:** CIDs are unforgeable
2. **Blind transport:** Relay doesn't inspect content
3. **Peer honesty:** Peers report accurate heads (verified by CID math)

### Limitations

| Limitation | Impact |
|------------|--------|
| **O(N) reconciliation** | BFS walk scales poorly for large graphs |
| **No freshness proofs** | Relay can withhold newer manifests |
| **No replay protection** | Old valid manifests can be re-sent |

---

## 6. Specification Structure

| Document | Purpose |
|----------|---------|
| [**Reconciliation**](reconciliation.md) | Heads, Delta, Comparison logic |
| [**Fulfillment**](fulfillment.md) | Portion transfer, ConvergenceReport |

---

## 7. References

- [IPFS Bitswap: Block Exchange Protocol](https://github.com/ipfs/specs/blob/main/BITSWAP.md)
- [Secure Scuttlebutt: Replication Protocol](https://github.com/ssbc/go-ssb#replication)
