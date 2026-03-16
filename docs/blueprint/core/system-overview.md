# System Overview: The Three-Layer Adhara

The Sovereign architecture is built on a radical separation of concerns. We split the system into three layers to ensure that truth remains at the edge and the infrastructure remains "Dumb and Blind."

---

## 1. The Core (L0: The Math)
The Core is the absolute basement of the system. It defines the mathematical laws that all Sovereign nodes must obey.

### The "Fortress" Mandate
The Core is designed as a strictly encapsulated "Black Box." 
*   **Encapsulation:** 100% of internal data fields are private. State is "Born Valid" through factory methods that enforce invariants at the moment of construction.
*   **Opaque Identifiers:** Foundational library types (like `cid::Cid`) are wrapped in domain-specific Newtypes (`BlockId`, `ManifestId`). This decouples the system's "Business Logic" from its "Library Physics."
*   **Hexagonal Isolation:** The Core is pure and side-effect free. It has no access to the clock, network, or filesystem.

## 2. The SDK (L1: The Brain)
The SDK is the only intelligent part of the system. It lives on the user's device and acts as the "Auditor" of the graph.
*   **The Job:**
    *   **Governance:** Walking the graph to verify that a signer has the authority to speak.
    *   **Privacy:** Handling all encryption and decryption.
    *   **Synchronization:** Managing the streaming "Conveyor Belt" with the Relay.
    *   **Projection:** Turning the DAG into a usable state for the application.
*   **The Trust:** The SDK is the only layer that holds the **GraphKeys**. It is the guardian of the user's agency.

## 3. The Relay (L2: The Pipe)
The Relay is a high-performance, zero-knowledge courier.
*   **The Job:** Hosting encrypted blobs, routing manifests, and helping devices find each other.
*   **The Constraint:** The Relay is **Blind**. It can verify the integrity of a CID (does the hash match the bytes?), but it cannot read the content or understand the Constitution of the graph. 
*   **The Benefit:** Because the Relay is dumb, it is cheap to run, easy to replace, and impossible to subpoena for user data.

---

## 4. The Interaction Loop: No Institutional Trust
1.  **Creation:** The user writes a message. The SDK encrypts it, hashes it into a CID, and signs a Manifest.
2.  **Transmission:** The SDK pushes the Manifest and the Blocks to the Relay. 
3.  **Consumption:** Another user’s SDK pulls the updates. It doesn't trust the Relay. It recalculates the CIDs, verifies the signatures, and checks the author’s Identity Graph. 
4.  **Acceptance:** If the math and the governance check out, the SDK integrates the new blocks into the local projection.

***

**Architect’s Note:** *This is the ultimate 'No Black Box' design. We have effectively turned the Relay into a commodity. If a Relay starts misbehaving, you just move your bytes to another one. The Truth stays with you.*
