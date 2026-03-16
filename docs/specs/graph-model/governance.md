---
title: "Graph Governance Specification"
subtitle: "The Right to Rule and Succession Rituals in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-02-23
---

# Graph Governance Specification

## 1. Introduction
This document defines the rules of authority over an individual Akshara graph. It specifies how the "Right to Rule" is established, inherited, and transferred within a decentralized Merkle-DAG history.

## 2. The Absolute Invariant
Governance in Akshara is rooted in the **Genesis Manifest**. 

*   **The Root Legislator:** The author of the genesis manifest (the manifest with no parents) is defined as the absolute authority for the lifetime of the graph, unless a formal succession event occurs.
*   **Agnostic Authority:** The Root Legislator may be a single user credential, a multi-signature threshold set, or a delegated institutional identity.

## 3. Causal Inheritance
Authority is inherited causally through the manifest timeline.

*   **Sequential Rule:** A manifest signed by an authorized credential is valid if it points to a parent manifest that was also authorized under the same identity context.
*   **Merge Convergence:** When merging forks, the resulting manifest MUST prove authority from all parent branches or establish a new authoritative head through a Legislator-level signature.

## 4. Ritual of Succession (Transfer of Ownership)
Ownership of a graph can be permanently transferred through a mathematical handover.

### 4.1 Succession Block (`akshara.succession.v1`)
The current Legislator signs a block containing:
*   **`target_identity_id`**: The public identifier of the new owner.
*   **`effective_cid`**: The CID of the manifest at which the handover occurs.

### 4.2 The Handover
1.  The original owner signs the Succession Block and pushes it to the graph.
2.  The new owner signs a **Handover Manifest** that points to the Succession Block and is anchored to the new owner's Identity Graph.
3.  **The Result:** The `Auditor` follows the chain of title. It accepts the original owner's signatures up to the handover point and only accepts the new owner's signatures thereafter.

## 5. Governance Models
Akshara supports pluggable governance patterns at the application level:

*   **Individual Agency:** A single user owns and legislates the graph.
*   **Institutional Stewardship:** A hospital or lab owns the graph and delegates "Executive" rights to doctors or technicians.
*   **Collective Ownership:** A group graph where a threshold of signatures is required for administrative updates.

## 6. Verification Invariants
*   **Legislative Primacy:** A signature from a credential derived from the **Legislator Branch** (`m/0'`) takes absolute precedence over any **Executive** (`m/1'`) signature in the event of a causal conflict.
*   **Immutability of Title:** The chain of ownership is recorded in the Merkle-DAG and cannot be erased or modified after the manifest has been distributed to peers.
