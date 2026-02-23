# Changelog: Akshara Aadhaara

All significant milestones of the Aadhaara foundation will be recorded here.

## [0.1.0-alpha.1] - 2026-02-19

### **Genesis Release: The Imperishable Foundation**

This is the initial versioned release of the **Akshara Aadhaara** (ಅಕ್ಷರ-ಆಧಾರ). It establishes the hardened cryptographic and mathematical laws of the Sovereign Web.

### **Foundational Capabilities**

#### **1. Content-Addressed Permanent Data**
- **Bit-Identical Serialization:** Mandated DAG-CBOR for all bitstreams to ensure identical CIDs across all CPU architectures.
- **Hierarchical Taxonomy:** Strict 0x50 (Block) and 0x51 (Manifest) multicodec enforcement.
- **Fortress Encapsulation:** Library-agnostic `Address` layer protects core logic from underlying hashing/transport physics.

#### **2. Causal Social Authority**
- **Master Key Binding:** Cryptographic proof that every graph belongs to a specific owner. Genesis manifests must be signed by the Master Root Key.
- **Identity Graph Traversal:** Real Merkle-walk verification of signer authority. Rejects revoked devices and temporal forgeries.
- **Auditor Module:** Dedicated trust gatekeeper separating navigation (geometry) from verification (legality).

#### **3. High-Concurrency Asynchronous Infrastructure**
- **Non-Blocking Storage:** Fully `async/await` compliant `GraphStore` trait.
- **Symmetric Convergence:** Reconciler identifies bi-directional knowledge gaps in a single exchange turn.
- **Stress-Tested Storms:** Verified head-pruning convergence under 50-thread concurrent pressure.

#### **4. Ergonomics & Telemetry**
- **Detailed Reporting:** High-level `converge` utility yields comprehensive metrics (synced counts, byte throughput).
- **Performance Baseline:** Benchmarked at ~250MB/s (MegaBytes) for bitstream processing (serialization and hashing) using an in-memory storage mock. 
    - *Note: Real-world throughput will be governed by the I/O latency of the chosen persistent `GraphStore` implementation.*
