---
title: "Graph Model Specification"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Graph Model Specification

## 1. Introduction
This document describes the Akshara Graph Model, which defines the topological and geometric laws for organizing data within a decentralized web. 

Akshara operates on the principle that **Everything is a Graph**. There are no "Files" or "Documents" in the foundational layer; instead, all information is represented as a collection of cryptographically linked nodes within a Directed Acyclic Graph (DAG).

## 2. Node Taxonomy
The graph model is composed of two fundamental node types, distinguished by their representational multicodecs:

1.  **Data Blocks ([Nodes](nodes.md)):** Atomic units of application data. They are encrypted at the source and linked recursively to form complex structures. (Multicodec: `0x50`).
2.  **Graph Manifests ([Snapshots](snapshots.md)):** Signed metadata nodes that capture a specific state of a graph. They provide the "Head" pointers for synchronization and authority. (Multicodec: `0x51`).

## 3. Structural Properties
*   **Merkle-DAG Integrity:** Every link in the graph is a Content Identifier (CID). This ensure that any modification to a leaf node causes a cascading change in CIDs up to the root, enabling instant tamper detection.
*   **Structural Sharing:** Graphs are immutable. When a graph is updated, only the modified nodes and their path to the root are newly created; all unchanged nodes are reused by reference, minimizing storage and synchronization overhead.
*   **Cycle Prevention:** Akshara mandates a strictly acyclic topology. Circular references are prohibited and MUST be detected during graph traversal to prevent infinite resolution loops.

## 4. Documentation Structure
*   [**Nodes**](nodes.md): Specification of Data Blocks, encryption envelopes, and recursive linking.
*   [**Snapshots**](snapshots.md): Specification of Manifests, header schemas, and timeline history.
*   [**Indices**](indices.md): Technical definition of the Merkle-Index used for human-readable path resolution (e.g., directory structures).
