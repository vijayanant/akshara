---
title: "Storage Semantics Specification"
subtitle: "Head Management and Resource Discovery Rituals"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-02-23
---

# Storage Semantics Specification

## 1. Introduction
This document defines the operational behavior of the Akshara storage layer. While the **Interface** defines the "What," the **Semantics** define the "How" of head-pruning, graph discovery, and data lifecycle management.

## 2. Head Management (The Frontier of Truth)
A "Head" is a manifest CID that has no children in the current local store. It represents the latest known state of a graph branch.

### 2.1 Head Pruning Algorithm
When `put_manifest(M)` is called, the store MUST perform the following atomic transaction:

1.  **Ingestion:** Store the bytes of manifest $M$ indexed by its CID.
2.  **Parent Scan:** Identify all manifests listed in the `M.parents` collection.
3.  **Registry Update:**
    *   **ADD** CID of $M$ to the `Heads` registry for the associated `graph_id`.
    *   **REMOVE** all CIDs found in Step 2 from the `Heads` registry.
4.  **Result:** The `Heads` registry now accurately represents the unmerged tips of the graph.

### 2.2 Convergence Integrity
To prevent "Head Explosion" (where a malicious actor pushes many unrelated manifests to one graph), implementations MUST enforce a limit on the number of concurrent heads allowed per `graph_id`.

*   **MAX_HEADS:** 50
*   **Enforcement:** Any manifest that would cause the number of concurrent heads to exceed 50 MUST be rejected until a merge manifest is produced. This protects the `Reconciler` from CPU and memory exhaustion during graph traversal.

## 3. Resource Discovery (Blind Handshakes)
Resource discovery is the mechanism by which one identity shares access with another without a centralized registry.

### 3.1 Lockbox Invariants
The `put_lockbox` operation is the primary unit of "Sharing at Rest."
*   **Blind Storage:** The store indexes lockboxes by the **Recipient's Public Key**. 
*   **Privacy:** The store MUST NOT attempt to link a public key to a real-world identity or an Identity Graph. It treats the public key as an opaque routing token.
*   **Automatic Cleanup:** Lockboxes SHOULD be treated as ephemeral transport units. Implementations MAY delete a lockbox once it has been successfully retrieved by the recipient.

## 4. Resource Lifecycle (Pinning and Deletion)
In a decentralized system, the life of a resource is controlled strictly by its authorized owner.
 The infrastructure MUST remain passive regarding data persistence.

*   **The Pinning Mandate:** The storage layer MUST NOT delete or "age out" data based on ambient metrics (e.g., last access time). All data associated with an active manifest is considered "Pinned."
*   **Explicit Erasure:** To delete data from a Relay, the authorized Legislator MUST push a signed **"Un-Pin" Manifest**. The storage layer MAY only reclaim space from blocks that are no longer reachable from any pinned manifest heads.
*   **Privacy of Deletion:** Because the Relay is blind, the only way to achieve absolute cryptographic erasure across the network is to rotate the **Symmetric Graph Key**, rendering the old blocks unreadable noise.
