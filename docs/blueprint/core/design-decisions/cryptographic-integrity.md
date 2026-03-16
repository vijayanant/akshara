# Design Decision: Cryptographic Integrity & Agility

## Context
To build a **Permanent Web**, we needed a data model that is indestructible, verifiable, and future-proof. We had to move away from the "Silo" model where data is tied to a database row.

---

## The Decision: Content-Addressed DAGs with Algorithm Agility

### 1. The Content-Addressed DAG Model
Every piece of data in Sovereign is an immutable **Block**. Blocks point to their ancestors and descendants, forming a Directed Acyclic Graph (DAG). 
*   **Integrity:** Any tampering with a block changes its ID, breaking the graph. 
*   **Deduplication:** Identical content results in the same ID, allowing the system to save space naturally.

### 2. Adopting CIDs (Algorithm Agility)
Instead of raw 32-byte hashes, we use **CIDv1 (Content Identifiers)**. 
*   **Why:** Raw hashes are "Blind." If SHA-256 is broken, the network dies. CIDs are self-describing; they include a prefix that tells the system which algorithm was used. 
*   **Impact:** We can upgrade the entire system to a new hash (e.g., BLAKE3) without invalidating historical data.

### 3. Strict Cipher Suite (The Sovereign Choice)
We have selected a "No Negotiation" set of algorithms to prevent downgrade attacks:
*   **Signing:** Ed25519.
*   **Handshake:** X25519.
*   **Encryption:** **ChaCha20-Poly1305** (AEAD). 

**Rationale for ChaCha20:** While AES is fast on servers, ChaCha20 is designed to be fast and safe on **any CPU** (Mobile/Edge) without requiring specialized hardware. We optimize for the user's device, not the landlord's cloud.

---

## Consequences
*   **Structural Trust:** We don't trust the server to be honest; we trust the math of the DAG to prove it.
*   **Permanent Links:** Sovereign links point to a CID, which is a mathematical fact. They never break.
*   **Complexity:** The SDK must handle "Forks" in the history (Scenario: two people edit the same parent while offline). We treat this as a human event, not a technical bug.

***

**Architect’s Note:** *This is our 'Satyata' (Truth) layer. By anchoring our names in math and our security in agile standards, we ensure that Sovereign data can survive for 50 years, regardless of where it is stored.*
