---
title: "Symmetric Reconciliation Specification"
subtitle: "LCA-Based Gap Detection in Merkle-DAGs"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Symmetric Reconciliation Specification

## 1. Introduction
Reconciliation is the process of identifying the difference between two separate views of a Merkle-DAG. This document defines the algorithm for determining the bi-directional knowledge gap between a local node and a remote peer.

## 2. Definitions
*   **Frontier (Heads):** The set of Manifest CIDs that have no children in a node's local store.
*   **Known Set:** The complete set of Manifest CIDs reachable by walking backwards from the Frontier.
*   **Surplus:** The set of CIDs present in one node's Known Set but absent in the other's.

## 3. Reconciliation Algorithm
The `Reconciler` performs a symmetric identification of knowledge in a single pass:

1.  **Input Exchange:** Peers exchange their current `Heads` for a specific `graph_id`.
2.  **Ancestry Calculation:** The Reconciler performs a Breadth-First Search (BFS) walk from both the local and remote heads to identify their respective Known Sets.
3.  **Symmetric Difference:**
    *   **`peer_surplus`**: `RemoteKnownSet - LocalKnownSet`. (Items to be downloaded).
    *   **`self_surplus`**: `LocalKnownSet - RemoteKnownSet`. (Items to be uploaded).
4.  **Delta Expansion:** For every manifest identified in the surplus, the Reconciler recursively identifies all associated data `BlockId`s (The Merkle-Index tree).
5.  **Output:** A `Comparison` struct containing the two identified `Delta` objects.

## 4. Resource Constraints
To prevent Denial-of-Service (DoS) and memory exhaustion, the following limits MUST be enforced:
*   **Head Limit:** A reconciliation request MUST be rejected if the number of heads provided exceeds **1024**.
*   **Delta Limit:** The Reconciler MUST terminate and return an error if an individual `Delta` expansion exceeds **100,000** addresses.

## 5. Implementation Invariants
*   **Stateless Execution:** The Reconciler logic MUST be deterministic and side-effect free. It identifies the gap based solely on the provided inputs and the current state of the `GraphStore`.
*   **Asynchronous Processing:** Reconciliation MUST be non-blocking to support concurrent synchronization turns across multiple graphs.
