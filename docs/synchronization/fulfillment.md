---
title: "Fulfillment and Telemetry Specification"
subtitle: "Data Delivery and Sync Progress Monitoring"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Fulfillment and Telemetry Specification

## 1. Introduction
Fulfillment is the process of delivering the physical bitstreams (Portions) identified during Reconciliation. This document defines the transport units and the functional telemetry generated during a synchronization turn.

## 2. The Atomic Unit: Portion
A **`Portion`** represents a single addressable unit of data in transit. 

### 2.1 Portion Schema
A Portion is encoded in DAG-CBOR and consists of:
*   **`id`**: The Akshara `Address` (CID) of the resource.
*   **`data`**: The raw, encrypted bitstream.

## 3. Fulfillment Protocol (Blind Pipe)
Akshara mandates a **Blind Fulfillment** loop to preserve the secrecy of the data:

1.  **Selection:** The provider iterates through the requested `Delta`.
2.  **Encapsulation:** For each CID, the provider fetches the raw bytes from the `GraphStore` and packages them into a `Portion`. 
3.  **Transmission:** The Portions are streamed to the remote peer.
4.  **Ingestion:** The receiver re-verifies the CID of each Portion before inserting it into their local `GraphStore`.

## 4. Functional Telemetry (ConvergenceReport)
Every synchronization turn MUST yield a **`ConvergenceReport`**. This report provides the high-level application with the metrics required for progress tracking and auditing.

### 4.1 Report Schema
*   **`manifests_synced`**: Count of 0x58 nodes successfully ingested.
*   **`blocks_synced`**: Count of 0x57 nodes successfully ingested.
*   **`total_bytes`**: Cumulative size of all data payloads transferred.

## 5. Error Recovery
*   **Atomic Failure:** If any individual `Portion` fails verification (hash mismatch), the entire synchronization turn MUST be considered failed. No partial state should be committed to the "Heads" registry.
*   **Idempotent Retries:** Because the protocol is content-addressed, a failed turn can be retried by requesting the same `Delta`. The local store will automatically ignore Portions it has already successfully persisted.
