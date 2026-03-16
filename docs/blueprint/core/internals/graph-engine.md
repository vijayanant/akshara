# Graph Engine: The Merkle Indexing Logic

A Graph in Sovereign is not a flat list of blocks. It is a **Merkle Tree**. This structure allows the system to scale infinitely without creating a "Fat Manifest" bottleneck.

---

## 1. The Anatomy of a Graph
Instead of a single list, we organize data into three distinct node types:

### 1.1 The Manifest (The Entry Point)
The Manifest is the signed root pointer of the graph. It is split into two logical components to ensure cryptographic and structural clarity.

#### 1.1.1 The ManifestHeader (The Content)
Groups the structural metadata into a single verifiable unit.
*   **graph_id:** The stable UUID of the graph.
*   **content_root:** CID pointing to the root Index Block.
*   **parents:** CIDs of previous Manifests (History).
*   **identity_anchor:** CID pointing to the author's Identity Graph.
*   **created_at:** Real system UNIX timestamp.

#### 1.1.2 The Proof (The Signature)
The Manifest also contains the `author`'s public key and a cryptographic `signature` covering the entire Header. This ensures that history is immutable and provenance is absolute.

### 1.2 Index Blocks (The Branches)
These are structural blocks that contain a map of keys to CIDs. They act like "Directories" in a file system.
*   **Format:** DAG-CBOR (Canonical Binary Object Representation).
*   **Structural Sharing:** When you update a single leaf node, you only create a new path of index blocks back to the root. The rest of the tree is reused (Structural Sharing).

### 1.3 Data Blocks (The Leaves)
These are the encrypted payloads containing the actual application data. To ensure safety, every data block uses a **unique random 96-bit nonce** for encryption.

---

## 2. Universal Addressing via Paths
Because the graph is a tree, we can use **Path-based Navigation**.
*   **Example:** `sov://[GraphID]/metadata/title`

### 2.1 Resolution Invariants (The Fortress)
Path resolution is a recursive operation. To protect the host system, the **Sovereign Resolver** enforces the following invariants:
1.  **Cycle Detection:** A single path resolution must never encounter the same CID twice. Any repetition is rejected as an integrity violation (*Satyata-viheen*).
2.  **Depth Limit:** Resolution is limited to **256 segments**. This protects the CPU and stack from exhaustion while remaining more than enough for any legitimate hierarchical application.
3.  **Existence Check:** A path only resolves if the final leaf CID exists in the local store. We do not resolve "Ghost Pointers."

---

## 3. The Scaling Payoff
1.  **Partial Sync:** A mobile device can sync the `/active_tasks` branch of a project without downloading the entire `/history` or `/archived` branches.
2.  **Deduplication:** Identical blocks (e.g., the same image in two different docs) are only stored once across the entire device.
3.  **Cross-Graph Links:** An index block can point to a CID in a *different* graph, enabling our "Linked Apps" vision.

***

**Architect’s Note:** *Moving from flat lists to trees is where we move from a toy project to a professional platform. It's more complex to implement, but the performance payoff is logarithmic, not linear. That's the only way to build for the long term.*
