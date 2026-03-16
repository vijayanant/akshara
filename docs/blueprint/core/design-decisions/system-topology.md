# Design Decision: System Topology & Transport

## Context
As the Sovereign codebase grew from a prototype to a universal platform, we faced two critical structural challenges:
1.  **Logic Leakage:** Ensuring that protocol-level logic (Layer 0) remains pure and portable (e.g., for WASM/Mobile) without being coupled to networking or storage IO.
2.  **Transport Efficiency:** Finding a communication protocol that supports high-frequency binary synchronization and streaming without the overhead of JSON or the fragility of raw WebSockets.

---

## The Decision: Multi-Crate gRPC Architecture

### 1. Monorepo Crate Separation
We have adopted a strict three-layer crate structure to enforce boundaries:
*   **`sovereign-core` (L0):** Pure logic, types, and math. Zero IO. This crate defines the "Laws of Physics" for our graphs.
*   **`sovereign-wire` (L1):** The gRPC schema and mapping layer. It defines the universal language for movement.
*   **`sovereign-sdk` (L1):** The "Edge Brain." Handles persistence, synchronization, and governance auditing.
*   **`sovereign-relay` (L2):** The "Blind Warehouse." A binary focused on storage and routing.

### 2. gRPC/Tonic as the Universal Pipe
We have selected **gRPC** (via the `tonic` crate) as the primary transport protocol, replacing earlier prototype ideas for REST or pure WebSockets.

**Rationale:**
*   **Protobuf Efficiency:** Serializes to dense binary, crucial for moving cryptographic keys and encrypted blobs. 
*   **Streaming Support:** Enables the "Conveyor Belt" sync model, where the Relay can push missing data as it finds it, rather than waiting for long round-trips.
*   **Strict Contracts:** Code generation ensures that the SDK and Relay always agree on the binary layout of a packet.

---

## Consequences
*   **Pakka Portability:** `sovereign-core` can be compiled for any target (Web, Mobile, CLI) because it has no dependencies on the operating system or network.
*   **High Performance:** gRPC handles multiplexing and compression, giving us "Snappy" sync out of the box.
*   **Boilerplate:** We accept the cost of writing `From/Into` mappings between Core and Wire types to maintain the purity of Layer 0.

***

**Architect’s Note:** *This topology is our 'No Black Box' foundation. By splitting the pipes (Wire) from the brain (SDK), we ensure that the system can evolve without breaking the core math.*
