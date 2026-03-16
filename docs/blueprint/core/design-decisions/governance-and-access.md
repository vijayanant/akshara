# Design Decision: Governance & Constitutional Access

## Context
Collaborative apps have wildly different rules. A "Family Photo" app is open; a "Medical Record" app is strictly hierarchical. We needed a platform that supports any model without hardcoding any specific rulebook.

---

## The Decision: Constitutional Governance at the Edge

### 1. Pluggable Governance (Block 0)
The rules of a graph are not in the code; they are **in the data**. Every graph includes a logically defined "Block 0" that acts as its Constitution. 
*   **The SDK Auditor:** When syncing, the SDK reads Block 0 and selects the appropriate Governance Provider (e.g., Monarch, Democracy, or Invitational) to verify the legitimacy of incoming blocks.

### 2. Lockbox-as-Data
Access to a graph is represented by a **Lockbox** (an encrypted key wrapper). 
*   **The Shift:** Instead of the Relay keeping a "List of Members," the Lockbox is just another block in the graph.
*   **Proof of Access:** If you can decrypt the Lockbox block, you have the `GraphKey`. If you have the `GraphKey`, the Constitution defines what you are allowed to do.

### 3. Capability-Based Security
We move from "Who are you?" (Identity) to "What can you prove?" (Capability). Every action in Sovereign is backed by a cryptographic proof.

---

## Consequences
*   **Immutable Rules:** No administrator (or Relay owner) can change the rules of a graph after it is created unless the Constitution allows it.
*   **Zero-Knowledge Permissions:** The Relay facilitating the sync doesn't know who is an "Admin" or a "Member." It only sees encrypted bitstreams.
*   **Revocation Storms:** Because un-sharing is a physical problem in a decentralized world, "kicking someone out" requires rotating the `GraphKey` and creating new Lockboxes for the remaining members.

***

**Architect’s Note:** *This is where we move from 'Data Sync' to 'Coordination.' By putting the law in the graph, we ensure that the user’s collaboration remains sovereign, regardless of which server it touches.*
