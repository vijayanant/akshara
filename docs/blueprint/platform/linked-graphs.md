# Linked Graphs: Interoperability in the Sovereign Web

The "App Era" failed because it locked data into proprietary silos. In the Sovereign Web, we break these cages. Because every interaction is modeled as a **Universal Graph**, different applications can reference each other’s state as easily as a web page links to an image.

## 1. The Reference Primitive (Cross-Graph URIs)
In our architecture, a "Link" is not a URL to a server; it is a **Sovereign URI** (`sov://[GraphID]`) pointing to a specific root identity.

### 1.1 The "Doctor/Patient" Scenario
Imagine a collaboration between two doctors and a patient:
1.  **Graph A (The Consultation):** A private group chat between Doctor 1 and Doctor 2.
2.  **Graph B (The Patient Record):** A highly sensitive medical history graph owned by the Patient.
3.  **The Link:** A block in Graph A contains a pointer to Graph B.

## 2. The Bridge: Capability Mounting
Linking to a graph is easy; **accessing** it securely is the challenge. We use **Nested Lockboxes**.

*   **The Mounting Process:** When Doctor 1 wants to refer Doctor 2 to the Patient Record, they don't send the data. They place a **Pointer Block** in the Chat Graph.
*   **The Content:** This block contains the `GraphID` of the Patient Record and a `Lockbox` containing the `GraphKey` for Graph B, encrypted for Doctor 2's public key.
*   **The Resolve:** When Doctor 2's SDK sees the pointer, it automatically "Mounts" Graph B into the local view.

## 3. Atomic Integrity across Boundaries
Because we use **CIDs**, a link from the Chat to a specific "X-Ray Block" in the Patient Record is **permanent and verifiable**. 
*   Even if the Patient Record graph is moved to a different Relay or archived on IPFS, the CID in the Chat Graph remains a valid mathematical proof of the data. 
*   Truth is preserved across the boundary of the apps.

## 4. The Unified Dashboard
This architecture allows the Sovereign SDK to provide a **Unified Projection**. A user doesn't open "The Chat App"; they open their **Sovereign Workspace**, which resolves the DAG of all their linked graphs (Chat, Medical, Tasks) into a single, cohesive experience.

***

**Architect’s Note:** *This is how we kill the Silo. By making 'Graphs pointing to Graphs' a first-class citizen of the platform, we allow developers to build ecosystems, not just apps. It’s more complex than a shared SQL database, but it’s the only way to achieve true data sovereignty.*
