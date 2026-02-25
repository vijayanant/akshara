---
title: "Graph Discovery and State Recovery Specification"
subtitle: "Stateless Reconstruction of User Data in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Graph Discovery and State Recovery Specification

## 1. Introduction
This document defines the protocols for maintaining a persistent index of a user's associated data graphs within their Identity Graph. This mechanism ensures that a user can reconstruct their entire digital state—including owned and shared graphs—using only their 256-bit entropy seed, without reliance on a centralized registry or hardware-specific backups.

## 2. The Resource Index
The Resource Index is a dedicated path within the Identity Graph used to track Graph Identifiers (UUIDs) and their associated access credentials.

### 2.1 Identity Graph Discovery (Isolated Identifiers)
To locate the Identity Graph associated with a specific resource on a Relay without revealing the user's global identity, a deterministic **Discovery ID** is utilized for each graph. 

*   **Derivation:** `DiscoveryId = HMAC-SHA256(MasterSeed, "akshara.v1.discovery" + GraphId)`
*   **Privacy:** Because the `DiscoveryId` is bound to the `GraphId`, the Relay cannot cluster different graphs belonging to the same user. Every resource appears to be owned by a unique, anonymous entity.

### 2.2 Graph Descriptor Schema
Each entry in the index points to a **Graph Descriptor Block** containing:
*   **`graph_id`:** The stable 128-bit identifier for the graph.
*   **`latest_manifest_id`:** (Optional) The last known-good snapshot CID.
*   **`label`:** (Optional) A human-readable identifier for local display.
*   **`enc_graph_key`:** The symmetric graph key, encrypted using the **Shared Keyring Secret** (Branch 4). This ensures that any authorized credential belonging to the identity can access the graph.

## 3. Resource Registration Workflow
When a new graph is created or a shared invitation is accepted, the client MUST update the Identity Graph to ensure the resource remains recoverable.

1.  **Entry Creation:** The client generates a Resource Descriptor Block.
2.  **Graph Update:** The block is inserted into the Identity Graph at `/resources/<owned|shared>/<graph_id_hex>`.
3.  **Audit:** The update is signed by an authorized Executive Key (Tier 3), following the delegation rules defined in the Authority Specification.

## 4. State Recovery Algorithm
State Recovery is the procedure for reconstructing the resource list on a fresh device.

1.  **Identity Recovery:** Reconstruct the Master Seed from the BIP-39 mnemonic and locate the latest Identity Manifest CID via the stable `DiscoveryId`.
2.  **Tree Resolution:** The client resolves the path `/resources/` within the recovered Identity Graph.
3.  **Recursive Discovery:**
    *   Iterate through all entries in `/resources/owned/` to identify user-authored graphs.
    *   Iterate through all entries in `/resources/shared/` to identify collaborative access.
4.  **Key Restoration:** For each entry, the client extracts and decrypts the `enc_graph_key` to restore access to the graph's content.
5.  **Re-synchronization:** The client uses the recovered `graph_id`s to query the network for the latest graph manifests.

## 5. Security Invariants
*   **Atomic Updates:** Registration of a new project and the update to the Identity Graph SHOULD be treated as a single logical transaction by the SDK to prevent "Floating Graphs" (graphs without an index entry).
*   **Credential Isolation:** Encryption of the `enc_graph_key` within the descriptor block MUST utilize the user's latest public encryption key to maintain forward secrecy.
