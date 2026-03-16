# Platform Primitives: The Language of the Universal Graph

To build a world where a "Chat" can point to a "Patient Record" without breaking the vault, we need a universal vocabulary. These are the primitives of the Sovereign platform—the tools we use to turn raw bytes into an *Akshara* (permanent) web.

---

## 1. The Block: The Atomic Unit
Every piece of data in Sovereign is a Block. A block is an encrypted, signed payload anchored by a **Content Identifier (CID)**.
*   **Physics:** A block never changes. If you change a single bit, you get a new CID. This is the foundation of our *Satyata*.
*   **Encapsulation:** To the network, a block is just a blob of noise. To the owner, it is a piece of meaning.

## 2. The Universal Graph: The Container
A "Graph" is a collection of blocks that share a permission boundary.
*   **GraphID:** A unique UUID that identifies the space.
*   **GraphKey:** The symmetric key that unlocks every block in that space.
*   **Scope:** If two pieces of data share the same key, they belong to the same Graph.

## 3. The Sovereign URI: Global Pointers
We replace the URL with the Sovereign URI. 
*   **Format:** `sov://[GraphID]/[BlockID]`
*   **Durability:** Unlike a web link, a Sovereign URI is permanent. It doesn't point to a server; it points to a mathematical proof. If the bytes exist anywhere in the frontier, the URI will find them.

## 4. The Merkle Index: Structural Navigation
Our graphs aren't just piles of blocks; they are **Trees**.
*   **Index Blocks:** These are structural "Branch" blocks that map human-readable paths (e.g., `/metadata/title` or `/chat/messages/42`) to CIDs.
*   **Structural Sharing:** When you update a single task in a 1,000-task board, the tree allows us to reuse 99% of the old blocks. Only the path from the root changes.

## 5. The Constitution: Pluggable Governance
We don't hardcode rules. Every graph has a "Block 0" that acts as its Constitution. 
*   **Authority Model:** The Constitution tells the SDK who is allowed to sign new manifests. 
*   **Flexibility:** A graph can be a Monarchy (one Master Key), a Democracy (a quorum of keys), or an Open Space (Invitational). The SDK enforces the law of the graph at the edge.

## 6. Projections: The App State
A graph is a history of events. An "App" is just a **Projection** of that history.
*   **Incremental Computing:** The SDK provides projectors that turn a DAG of blocks into a usable state (like a sorted task list) in real-time. 
*   **Interoperability:** Because the primitives are universal, different apps can project the same graph into different views (e.g., a Chat app and a Wiki app viewing the same document).

---

**Architect’s Note:** *These primitives are our "Glass Abstractions." We aren't hiding the complexity of the graph; we are giving developers the vocabulary to navigate it.*