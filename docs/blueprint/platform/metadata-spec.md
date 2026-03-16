# The Constitution: Governance at the Edge

A Sovereign Graph is more than just data; it is a **Governed Space**. Every graph contains its own "Law of the Land" in its genesis metadata—logically referred to as **Block 0**.

## 1. The Block 0 Convention
The very first block in a graph's history defines its **Constitution**. This block is immutable and signed by the creator. All subsequent manifests are audited by the SDK against this constitutional root.

## 2. Pluggable Governance Models
We do not hardcode authority. Instead, Block 0 specifies a **Governance Provider**.

### 2.1 The Monarchy Model (Authoritarian)
*   **Logic:** A single "Master Key" (Tier 1) has absolute authority.
*   **Activity:** Daily edits are signed by Device Keys (Tier 2), but those keys must have a valid, unrevoked delegation block in the Identity Graph originating from the Master Key.
*   **Revocation:** Instant and absolute by the Master Key.

### 2.2 The Invitational Model (Shared Secret)
*   **Logic:** Possession of the `GraphKey` (the ability to read) implies the authority to edit (the ability to write).
*   **Use Case:** Informal groups, family sharing, and peer-to-peer chats.
*   **Trust:** Structural trust—if you're in the room, you're a member.

### 2.3 The Consensus Model (Democratic)
*   **Logic:** Significant changes (e.g., inviting new admins or "sealing" a version) require a $K$-of-$N$ threshold of signatures.
*   **Enforcement:** The SDK Auditor will reject any "Constitutional Update" that lacks the required number of cryptographic proofs.

## 3. The Capability Audit (L1 Enforcement)
The Sovereign SDK acts as the "Judge." Before integrating a new block from the Relay, the SDK performs a **Capability Audit**:
1.  **Identity Check:** Is the signature valid?
2.  **Timeline Check:** Was the signing key authorized according to the author's Identity Graph at that moment?
3.  **Constitution Check:** Does the author hold the "Capability" to write this type of block according to Block 0?

***

**Architect’s Note:** *This is the heart of RFC-008. By putting the rules IN the graph, we ensure that no Relay can ever perform a 'Coup' or change the rules of your collaboration. The math enforces the law, and the SDK is the only auditor.*
