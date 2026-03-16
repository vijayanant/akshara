# Addressing and Content Identifiers (CIDs)

## 1. Introduction: The Death of the Hardcoded Hash
If we hardcode SHA-256 today, our system dies the moment SHA-256 is broken. To build an *Akshara* (permanent) web, we must have **Algorithm Agility**. 

Sovereign adopts the **CIDv1 (Content Identifier)** standard. Every piece of data in the ecosystem is self-describing: the ID itself tells the system which algorithm was used to create it and how to interpret the bytes it points to.

---

## 2. The Implementation: Newtype Fortress
Identifiers are not raw bitstreams; they are **First-Class Domain Citizens**. 
*   **The Problem:** Exposing library-specific types (like `cid::Cid`) allows "Physics Leakage," where downstream code depends on internal implementation details.
*   **The Sovereign Solution:** We use **Newtype Wrappers** with **Private Fields**.
    *   `BlockId(Cid)`
    *   `ManifestId(Cid)`
*   **Invariant Enforcement:** Because the fields are private, identifiers can **only** be created through validated factory methods (`from_sha256`, `try_from`). This ensures that every ID in the system is cryptographically sound and follows our Multicodec laws.

---

## 3. The Binary Structure
A Sovereign CID follows the standard [CIDv1 specification](https://github.com/multiformats/cid). It is a prefix-encoded bitstream:

`[Version][Multicodec][Multihash_Type][Digest]`

### 3.1 Component Codes
We reserve the following identifiers for our protocol:
*   **Version:** `0x01` (CIDv1).
*   **Multicodec (Format):**
    *   `0x50`: **Sovereign Block** (The encrypted leaf).
    *   `0x51`: **Sovereign Manifest** (The signed entry point).
    *   `0x71`: **DAG-CBOR** (Index and structural blocks).
*   **Multihash (Default):**
    *   `0x12`: **SHA2-256** (The 32-byte workhorse).

---

## 4. The Wire Format
In the gRPC protocol and local storage, we handle CIDs as **raw bytes** for maximum efficiency. 

### 4.1 Strict Ingestion (The Fortress Rule)
A Sovereign CID parser must follow the **Strict Ingestion** rule: every bit of the input buffer must be accounted for. 
*   **The Trap:** Standard libraries often ignore trailing bytes at the end of a buffer.
*   **The Sovereign Law:** If a buffer contains extra data after the CID is parsed, the ID is rejected as malformed. This prevents attackers from hiding malicious tags or extra entropy inside our identifiers.

**Example (A SHA-256 Sovereign Block):**
| Byte | Value | Meaning |
| :--- | :--- | :--- |
| 0 | `0x01` | CIDv1 |
| 1 | `0x50` | It's a Sovereign Block |
| 2 | `0x12` | Hashed with SHA-256 |
| 3 | `0x20` | Digest is 32 bytes long |
| 4-35 | `[...]` | The raw digest bytes |

---

## 5. Why this is "Pakka" Architecture
By using CIDs, we decouple the "Name" of the data from the "Technology" of the data. 
1.  **Future Proof:** If we move to BLAKE3 or SHA-3, we just change the prefix. Legacy nodes will know how to find the old data, and new nodes will know how to verify the new data. 
2.  **IPFS Ready:** Because we follow the CID standard, any block in Sovereign is natively compatible with the global IPFS network.

***

**Architect’s Note:** *This is the foundation of Algorithm Agility. We are building for the next 50 years, not the next 5 months. No jugaad here.*
