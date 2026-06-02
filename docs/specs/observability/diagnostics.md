# Spec: Observability & Diagnostics

**Status:** Draft — For Review  
**Date:** 2026-06-02  
**Cross-references:** [Errors](../api/errors.md), [Sync](../api/sync.md), [Client & Graph](../api/client-and-graph.md)

---

## Scope

This specification defines the observability and diagnostics architecture for the `akshara` and `akshara-aadhaara` crates. It details the structured tracing schemas, metrics KPIs, developer-mode DAG visualizer API, and rich error context models needed to troubleshoot cryptographic sync and validation states safely.

---

## 1. Core Philosophies & Privacy Whitelist

In a zero-trust architecture, debugging telemetry must never compromise privacy. Observability is restricted to **mathematical execution** and **latency characteristics** while strictly forbidding logging of secrets, plaintexts, or user metadata.

### 1.1 Strictly Forbidden (Never log or export)
- **Secrets**: Cryptographic private keys, mnemonics, seeds, nonces, decrypter instances.
- **Plaintext Content**: Raw file data, document contents, path values that contain sensitive terms.
- **Metadata Leakage**: Raw network peer IP addresses or unhashed user identifiers.

### 1.2 Whitelisted Attributes (Safe for telemetry/spans)
- Graph Identifiers (`graph_id`).
- Merkle Address CIDs (Manifest ID, Block ID).
- Blinded Discovery IDs (`Lakshana`).
- Path structures (standard directory prefixes, e.g., `/patient/demographics` or `.akshara.trust/`).
- Cache state (hit/miss status).
- Execution stats (recursive iteration depth, database latency).

---

## 2. Structured Tracing Schema

We utilize the `tracing` crate to propagate spans across asynchronous task boundaries. Spans group operations logically and carry standard metadata.

### 2.1 Standard Spans

| Span Name | Target | Level | Span Fields |
| :--- | :--- | :--- | :--- |
| `sync_session` | `SyncEngine::sync_graph` | `INFO` | `graph_id: GraphId`, `peer_id: String` |
| `audit_manifest` | `Auditor::audit_manifest` | `DEBUG` | `manifest_id: ManifestId`, `graph_id: GraphId` |
| `audit_block` | `Auditor::audit_block` | `DEBUG` | `block_id: BlockId` |
| `verify_authority` | `IdentityGraph::verify_authority` | `DEBUG` | `identity_anchor: ManifestId`, `key_to_verify: String` |
| `resolve_path` | `GraphWalker::resolve_path` | `TRACE` | `graph_id: GraphId`, `path: String` |

### 2.2 Parent-Child Trace Propagation
Every recursive cycle inside the Merkle Index walk during pull synchronization must be executed within the context of the parent `sync_session` span to allow debuggers to trace the flow of CIDs sequentially.

---

## 3. Developer DAG Visualizer API

To avoid developers flying blind due to encryption, the SDK exposes a visualization API in **debug builds** or under the `diagnostics` compile feature gate.

```rust
impl Graph {
    /// Generates a structured ASCII diagram representing the logical view of the
    /// Merkle-DAG's index tree and historical manifests, decrypted via the local GraphKey.
    ///
    /// # Errors
    /// Returns `Error::Decryption` if the graph key is invalid.
    pub async fn visualize_dag(&self) -> Result<String, Error>;
}
```

### 3.1 Sample Output Format

```text
Graph ID: c4ceb3cb-020b-486c-8ba9-508472db6e67
├── [Manifest] bafmbeibkhg5el3... (sealed by: Priya [Legislator])
│   ├── [Index] baflreig6zao...
│   │   ├── /patient/demographics ➔ [Data Block] baflreia4aag7...
│   │   └── /patient/allergies ➔ [Data Block] baflreiawvav3...
│   └── [Anchor] bafmbeigagak3f... (Identity Graph)
│
└── [Manifest] bafmbeigms5dum... (sealed by: Priya [Legislator])
    ├── [Parent] bafmbeibkhg5el3...
    └── [Index] baflreih65rk...
        ├── .akshara.trust/87862d9f... ➔ [Trust Block] baflreig6za... (Authorizes: Dr. Mehta)
        └── [Lockbox] 9abd47cf... ➔ [Recipient: Dr. Mehta]
```

---

## 4. Rich Diagnostic Errors

Error objects returned by the SDK must carry structured context to enable programmatic troubleshooting of key mismatches and authority failures.

### 4.1 Error Variants Context

```rust
#[derive(Debug, Clone)]
pub struct GraphIdMismatchContext {
    pub expected: GraphId,
    pub actual: GraphId,
    pub manifest_id: ManifestId,
}

#[derive(Debug, Clone)]
pub struct UnauthorizedSignerContext {
    pub signer: SigningPublicKey,
    pub graph_id: GraphId,
    pub checked_path: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct DecryptionFailedContext {
    pub block_id: BlockId,
    pub graph_id: GraphId,
    pub reason: String,
}
```

These structs are attached directly to their corresponding `akshara::Error` variants, superseding string-only descriptions.

---

## 5. Diagnostic Metrics (KPIs)

We record statistics via the `metrics` facade. Keys are namespaces for easy filtering.

- `sovereign.sync.pull_depth`: Counter for the number of recursive index levels walked.
- `sovereign.cache.identity_roots.hit_ratio`: Gauge representing memory lookup success rate for the validation cache.
- `sovereign.vault.decryption_failures.count`: Monotonic counter representing block decryption failures (indicates corrupt storage or key out-of-sync).
- `sovereign.walker.path.resolution_time_ms`: Histogram tracking latency of directory walks.
