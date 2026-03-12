---
title: "Graph Snapshots Specification"
subtitle: "Manifests and Timeline Integrity in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Graph Snapshots Specification

## 1. Introduction
This document defines the structure and verification rules for **Graph Manifests** (Snapshots). Manifests are signed metadata nodes that establish the authoritative "Head" of a graph at a specific point in time.

## 2. Snapshot Identifier (ManifestId)
All Graph Manifests MUST utilize an address with the **`0x58`** multicodec. This prevents type-confusion attacks where a data block could be mistaken for an authoritative snapshot.

## 3. Manifest Structure
A Manifest is encoded using **Canonical DAG-CBOR** and consists of:

*   **`id`:** The `ManifestId` derived from the header hash.
*   **`header`:** The structural metadata (see Section 4).
*   **`author`:** The public signing key of the credential.
*   **`signature`:** A signature over the `id`.

## 4. Manifest Header Schema
The header defines the identity, state, and history of the graph:

*   **`graph_id`:** The stable 128-bit identifier for the resource.
*   **`content_root`:** The `BlockId` of the top-level node in the content tree.
*   **`parents`:** A collection of `ManifestId`s representing previous snapshots (The Timeline).
*   **`identity_anchor`:** The `ManifestId` of the Identity Graph manifest used to verify authority.
*   **`created_at`:** A Unix timestamp (Metadata only; not used for causal decisions).

## 5. Timeline Integrity
The `parents` field enables the construction of a persistent, verifiable timeline of state changes.

*   **Linear History:** A single parent represents a sequential update.
*   **Merge State:** Multiple parents represent the convergence of concurrent edits.
*   **Genesis:** An empty parents collection identifies the origin of the graph.

## 6. Authority Binding
Every manifest is cryptographically bound to an **Identity Graph**. The `identity_anchor` provides the context for the `Auditor` to perform the causal walk required to verify the author's credentials at the moment the snapshot was created. 

Any manifest signed by a credential that was revoked or unauthorized at the point of the `identity_anchor` MUST be rejected as invalid.
