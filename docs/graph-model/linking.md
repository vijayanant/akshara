---
title: "Cross-Graph Linking Specification"
subtitle: "The Law of the Bridge and Constellation Authority"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Cross-Graph Linking Specification

## 1. Introduction
This document defines the protocols for establishing secure, verifiable links between separate Akshara graphs. It specifies how authority is bridged across different owners to enable "Resource Constellations" while maintaining absolute cryptographic integrity.

## 2. The Link Model
A **Link** is a Content Identifier (CID) residing within a source graph that points to a manifest in a target graph.

### 2.1 Intra-Identity Link (Self-Link)
A link where the target graph is anchored to the **same identity root** as the source. 
*   **Requirement:** NO Bridge Block is required. The `Auditor` inherently trusts any graph anchored to the same root of trust.

### 2.2 Inter-Identity Link (The Bridge)
A link where the target graph is owned and anchored by a **different identity root**.
*   **Requirement:** A **Trust Delegation Block** MUST be present in the source graph to authorize the third-party signature.

## 3. Trust Delegation (The Bridge Block)
To enable verifiable Inter-Identity linking, the source graph MUST contain a **Trust Delegation Block**.

### 3.1 Block Schema (`akshara.trust.v1`)
*   **`target_root_key`:** The Master Public Key of the third-party identity being trusted.
*   **`scope`:** The permission set granted (e.g., `akshara.resource.read`).
*   **`path_mask`:** (Optional) Limits the trust to specific sub-paths within the source graph.
*   **`expiration`**: A Merkle-depth limit for the delegation.

## 4. Verification Algorithm (The Bridge Walk)
When the `Auditor` encounters an Inter-Identity link during traversal:

1.  **Identity Detection:** The Auditor observes that the target manifest's `author` is not authorized within the current graph's identity context.
2.  **Bridge Discovery:** The Auditor performs a recursive walk of the source graph's ancestors to locate a valid `akshara.trust.v1` block matching the target author's root identity.
3.  **Validity Check:** If no bridge block is found, or if the bridge has expired, the link is REJECTED.
4.  **Causal Handover:** If a bridge is found, the Auditor "jumps" to the target identity's Identity Graph to verify the target manifest's signature using the rules defined in the Authority Specification.

## 5. Privacy: Transitive Key Transport
Possessing a link does not grant the ability to read the content. Access depends on possessing the target graph's symmetric key.

*   **Linkage Logic:** The source graph SHOULD include an encrypted **Transitive Lockbox** for any collaborator who is granted access to the constellation.
*   **Payload:** This lockbox contains the symmetric keys for the linked target graphs, re-encrypted for the collaborator's public key.

## 6. Integrity Invariants
*   **Bit-Permanence of Trust:** Because the Bridge Block is hashed into the Merkle-DAG, the "Trust" is immutable for that specific version of the graph.
*   **Explicit Revocation:** Trust is revoked by issuing a new manifest that omits the Bridge Block or includes a specific Revocation of Trust tombstone.
