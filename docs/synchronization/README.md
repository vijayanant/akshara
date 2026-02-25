---
title: "Synchronization Specification"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Synchronization Specification

## 1. Introduction
This document describes the Akshara Synchronization protocol, which defines the mathematical and procedural rules for converging data across separate Merkle-DAG instances.

Akshara adopts a **Symmetric Convergence** model. Unlike traditional Client-Server protocols where one party is the authoritative provider and the other is the requester, Akshara treats all peers as equal participants in a shared field of knowledge. Synchronization is the process of identifying and resolving the bi-directional gap between two frontiers of truth.

## 2. Convergence Model
The protocol is designed to operate over a "Blind Pipe" transport, ensuring that the infrastructure facilitating the sync never gains access to the decrypted content or the social authority laws of the graph.

The synchronization layer is composed of two primary technical components:

1.  **Symmetric Reconciliation ([Reconciliation](reconciliation.md)):** The algorithm for identifying the "Surplus" knowledge of each peer using Lowest Common Ancestor (LCA) graph walks.
2.  **Blind Fulfillment ([Fulfillment](fulfillment.md)):** The protocol for delivering encrypted bitstreams (Portions) to fill identified gaps, accompanied by functional telemetry.

## 3. Core Properties
*   **Location Independence:** Synchronization can occur between an SDK and a Relay, or directly between two SDK instances (P2P), using the same mathematical logic.
*   **Atomic Convergence:** Peers identify all missing resources in a single exchange turn, minimizing network round-trips.
*   **Functional Telemetry:** Every synchronization turn yields a structured report on manifests, blocks, and bytes processed, enabling high-level progress monitoring and auditing.

## 4. Documentation Structure
*   [**Reconciliation**](reconciliation.md): Specification of the `Heads`, `Delta`, and `Comparison` logic.
*   [**Fulfillment**](fulfillment.md): Specification of the `Portion` transfer protocol and the `ConvergenceReport`.
