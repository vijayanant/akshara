---
title: "Fulfillment and Telemetry Specification"
subtitle: "Data Delivery and Sync Progress Monitoring"
version: "0.1.0-alpha.2"
status: "Accepted"
date: "2026-03-14
---

# Fulfillment and Telemetry Specification

## 1. Motivation

### The Problem

Reconciliation identified the gaps. Now what?

- **How do we transfer the data?** Streaming? Batch?
- **How do we verify integrity?** Trust but verify?
- **How do we track progress?** "Syncing... 45%"
- **What if transfer fails?** Retry? Partial state?

### The Akshara Solution

**Fulfillment** — blind data delivery with verification:

```
Reconciliation → Comparison { peer_surplus, self_surplus }
                      ↓
Fulfillment → Stream Portions → Verify CIDs → Ingest → Report
```

**Key properties:**
- **Blind:** Relay doesn't inspect content
- **Verified:** CID checked before ingest
- **Atomic:** All-or-nothing; no partial state
- **Idempotent:** Safe to retry

---

## 2. Overview

Fulfillment is the process of delivering the physical bitstreams (Portions) identified during Reconciliation. This document defines the transport units and the functional telemetry generated during a synchronization turn.

### Key Concepts

| Term | Meaning |
|------|---------|
| **Portion** | Single addressable unit of data in transit |
| **Convergence Report** | Telemetry: manifests synced, blocks synced, bytes |
| **Atomic Failure** | All-or-nothing; no partial state on error |
| **Idempotent Retry** | Safe to retry; duplicates automatically ignored |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Fulfillment Flow                                           │
│                                                             │
│  Provider                         Consumer                  │
│                                                             │
│  1. Iterate Delta                                           │
│     for cid in delta:                                       │
│       data = store.get(cid)                                 │
│                                                             │
│  2. Create Portions                                         │
│     portion = Portion { id: cid, data: data }               │
│                                                             │
│  3. Stream Portions ──────────────────→                     │
│                                         │                   │
│  4. Verify & Ingest                     │                   │
│     computed_cid = hash(portion.data)   │                   │
│     if computed_cid == portion.id:      │                   │
│       store.put(portion)                │                   │
│                                                             │
│  5. Generate Report                     │                   │
│     report = ConvergenceReport {        │                   │
│       manifests_synced: 15,             │                   │
│       blocks_synced: 42,                │                   │
│       total_bytes: 131072               │                   │
│     }                                   │                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. The Atomic Unit: Portion

A **`Portion`** represents a single addressable unit of data in transit.

### 3.1. Portion Schema

A Portion is encoded in **Canonical DAG-CBOR**:

```cbor
{
  "id": <Address/CID>,      // Content identifier
  "data": <raw bytes>       // Encrypted bitstream
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | Address (CID) | Content identifier (0x57 for blocks, 0x58 for manifests) |
| `data` | bytes | Raw encrypted data (DAG-CBOR encoded) |

### 3.2. Portion Types

| Type | Multicodec | Content |
|------|------------|---------|
| **Manifest Portion** | `0x58` | Signed manifest header |
| **Block Portion** | `0x57` | Encrypted data block |
| **Index Portion** | `0x57` (type="index") | Encrypted index map |

---

## 4. Fulfillment Protocol

### 4.1. Provider Side (Sending)

```
Input:  delta (Delta), store (GraphStore)
Output: Stream of Portions

1. portions = []
2. manifest_count = 0
3. block_count = 0
4. total_bytes = 0

5. // Iterate in reverse topological order (heads first)
6. for cid in delta.reverse_topological_order():
       data = store.get_bytes(cid)
       if data is null:
           continue  // Missing data; skip

       portion = Portion {
           id: cid,
           data: data
       }

       portions.push(portion)
       total_bytes += len(data)

       if cid.is_manifest():
           manifest_count++
       else:
           block_count++

7. Return portions, manifest_count, block_count, total_bytes
```

### 4.2. Consumer Side (Receiving)

```
Input:  portions (stream), store (GraphStore)
Output: success (bool), report (ConvergenceReport), error (optional)

1. ingested = []
2. manifest_count = 0
3. block_count = 0
4. total_bytes = 0

5. for portion in portions:
       // Verify CID
       computed_cid = CID(multicodec(portion.data), SHA2-256(portion.data))
       if computed_cid != portion.id:
           // Atomic failure: rollback all ingested portions
           for cid in ingested:
               store.remove(cid)  // Or mark as invalid
           return false, null, "CID mismatch for " + portion.id

       // Ingest
       store.put(portion.id, portion.data)
       ingested.push(portion.id)

       total_bytes += len(portion.data)
       if portion.id.is_manifest():
           manifest_count++
       else:
           block_count++

6. // Update heads registry
7. for cid in ingested:
       if cid.is_manifest():
           heads.add(cid)

8. report = ConvergenceReport {
       manifests_synced: manifest_count,
       blocks_synced: block_count,
       total_bytes: total_bytes
   }

9. Return true, report, nil
```

### 4.3. Reverse Topological Ordering

Portions MUST be streamed **heads first** (parents after children):

```
Correct Order:
  Manifest C (head) → Manifest B → Manifest A (genesis)
  (Receiver can verify C's parent reference before C arrives)

Wrong Order:
  Manifest A → Manifest B → Manifest C
  (Receiver must buffer; can't verify until all arrive)
```

**Why:** Allows receiver to verify parent references before ingesting child.

---

## 5. Functional Telemetry (ConvergenceReport)

Every synchronization turn MUST yield a **`ConvergenceReport`**.

### 5.1. Report Schema

```cbor
{
  "manifests_synced": <u64>,    // Count of 0x58 nodes ingested
  "blocks_synced": <u64>,       // Count of 0x57 nodes ingested
  "total_bytes": <u64>,         // Cumulative payload size
  "duration_ms": <u64>,         // Time taken (optional)
  "peer_id": <string>           // Peer identifier (optional)
}
```

### 5.2. Usage Example

```rust
let (success, report) = sync_with_peer(&peer).await?;

if success {
    println!("Synced {} manifests, {} blocks ({:.2} KB)",
        report.manifests_synced,
        report.blocks_synced,
        report.total_bytes as f64 / 1024.0
    );
} else {
    eprintln!("Sync failed; will retry");
}
```

---

## 6. Error Recovery

### 6.1. Atomic Failure

If any individual `Portion` fails verification:

```
1. CID mismatch detected for portion X
2. Rollback all previously ingested portions
3. Return error; do not update heads registry
4. Consumer state unchanged (as if sync never happened)
```

**Rationale:** Partial state is inconsistent state.

### 6.2. Idempotent Retries

Because the protocol is content-addressed:

```
Retry Logic:
1. Re-request same delta
2. Consumer already has some portions (from previous attempt)
3. store.put() is idempotent (duplicate CIDs ignored)
4. Only missing portions are actually ingested
5. Report reflects only newly ingested data
```

**Rationale:** Network failures are common; retry must be safe.

---

## 7. Test Vectors

### Test Vector 1: Successful Fulfillment

```
Input:
  Delta: [CID_A, CID_B, CID_C]
  Store (provider): Has all three
  Store (consumer): Empty

Process:
  1. Provider streams: Portion(A), Portion(B), Portion(C)
  2. Consumer verifies each CID
  3. All match; ingest successful

Expected Report:
  manifests_synced: 3
  blocks_synced: 0
  total_bytes: 1536  // Example size
```

### Test Vector 2: CID Mismatch (Atomic Failure)

```
Input:
  Delta: [CID_A, CID_B, CID_C]
  Store (provider): Has all three
  Store (consumer): Empty

Process:
  1. Provider streams: Portion(A), Portion(B), Portion(C)
  2. Consumer verifies A → OK, ingests
  3. Consumer verifies B → OK, ingests
  4. Consumer verifies C → MISMATCH!
  5. Rollback A and B
  6. Return error

Expected Result:
  success: false
  Consumer state: Empty (A and B rolled back)
```

### Test Vector 3: Idempotent Retry

```
Input:
  Delta: [CID_A, CID_B, CID_C]
  Store (provider): Has all three
  Store (consumer): Has A (from previous attempt)

Process:
  1. Provider streams: Portion(A), Portion(B), Portion(C)
  2. Consumer verifies A → Already exists; skip
  3. Consumer verifies B → OK, ingests
  4. Consumer verifies C → OK, ingests

Expected Report:
  manifests_synced: 2  // Only B and C (A was already present)
  blocks_synced: 0
  total_bytes: 1024    // Only B + C bytes
```

---

## 8. Security Considerations

### What This Protects Against

| Threat | Mitigation |
|--------|------------|
| **Data injection** | CID verification before ingest |
| **Corrupted transfer** | Hash mismatch detection |
| **Partial state attacks** | Atomic rollback on failure |
| **Replay attacks** | Idempotent put; duplicates ignored |

### Assumptions

1. **Content-addressed integrity:** CIDs are unforgeable
2. **Honest provider:** Provider sends correct data for CIDs
3. **Reliable transport:** Portions arrive unmodified

### Limitations

| Limitation | Impact |
|------------|--------|
| **No encryption in transit** | Assumes transport-layer encryption (TLS, etc.) |
| **No compression** | Raw bytes sent; may be inefficient |
| **All-or-nothing** | Large deltas may fail entirely on single error |

---

## 9. References

- [Synchronization Overview](README.md)
- [Reconciliation Specification](reconciliation.md)
- [Data Nodes Specification](../graph-model/nodes.md)
