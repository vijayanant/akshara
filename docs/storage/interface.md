---
title: "Storage Interface Specification"
subtitle: "The GraphStore Trait and Atomic API Laws"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Storage Interface Specification

## 1. Introduction
This document defines the **`GraphStore`** trait, which serves as the primary interface between the Akshara logic and the physical storage medium. All implementations MUST adhere to these non-blocking, asynchronous standards.

## 2. Core API
The interface is divided into functional domains for data, metadata, and discovery.

### 2.1 Data Block Operations
*   **`put_block(block: &Block)`**: Persists an encrypted data unit.
*   **`get_block(id: &BlockId)`**: Retrieves a block by its identifier.

### 2.2 Graph Snapshot Operations
*   **`put_manifest(manifest: &Manifest)`**: Persists a signed graph snapshot and updates the "Heads" registry.
*   **`get_manifest(id: &ManifestId)`**: Retrieves a manifest by its identifier.
*   **`get_heads(graph_id: &GraphId)`**: Returns the current frontier (unmerged manifests) for a specific graph.

### 2.3 Discovery Operations
*   **`put_lockbox(recipient, lockbox)`**: Stores a discovery credential for a specific public key.
*   **`get_lockboxes(recipient)`**: Retrieves all pending invitations for a specific public key.

## 3. Operational Invariants
Every `GraphStore` implementation MUST guarantee the following properties:

1.  **Representational Integrity:** The store MUST verify the cryptographic hash of every object during the `put` operation. If the CID does not match the payload, the operation MUST return an `IntegrityError`.
2.  **Idempotency:** Saving the same CID multiple times MUST be a no-op and return `Ok(())`. The store MUST NOT duplicate storage for identical content.
3.  **Atomic Head Pruning:** When a new manifest is stored, the `GraphStore` MUST atomically update the graph's "Heads" registry by adding the new CID and removing any of its immediate `parents`.
4.  **Send + Sync:** All implementations MUST be thread-safe to support high-concurrency execution environments.

## 4. Error Semantics
Implementations MUST return context-rich errors utilizing the `SovereignError::Store` variant:
*   **`NotFound`**: Returned when a requested CID does not exist in the store.
*   **`Conflict`**: Returned if an atomic update violates a storage-level constraint (e.g., locking).
*   **`IOError`**: Returned for underlying physical failures (disk full, network timeout).
