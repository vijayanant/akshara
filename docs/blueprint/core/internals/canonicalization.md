# Canonicalization: Ensuring Structural Satyata

The core of Sovereign is Content Addressing. But Content Addressing depends on a fundamental truth: **If two systems agree on the meaning of data, they must agree on the bytes.** 

In our current web, this is rarely true. UTF-8 vs. UTF-16, Tab vs. Space, and JSON key ordering create "environmental noise" that changes the hash without changing the meaning. In Sovereign, we eliminate this noise through **Strict Canonicalization**.

## 1. The Adhara: DAG-CBOR
Sovereign adopts **DAG-CBOR** (a restricted subset of RFC 8949) as its primary serialization format for all structural data (Manifests, Index Blocks, and Identity Blocks).

Unlike standard JSON or CBOR, DAG-CBOR enforces:
*   **Strict Key Sorting:** All map keys must be sorted lexicographically by their encoded bytes.
*   **Integer Minimization:** Integers must be encoded in the smallest possible number of bytes.
*   **No Duplicates:** Duplicate keys are mathematically forbidden.

This ensures that every Sovereign node, regardless of architecture or implementation, arrives at the exact same CID for the same logical content.

## 2. Text Canonicalization
For application data containing text (Data Blocks), Sovereign mandates **UTF-8** with **Normalization Form C (NFC)**.
*   **The Trap:** Many operating systems represent "accents" differently (e.g., a single character vs. a letter plus a combining mark). 
*   **The Law:** The SDK must normalize all text to NFC before hashing. This ensures that a document created on a Mac has the exact same CID when viewed on a Linux server.

## 3. The Implementation Constraint: No "Jugaad" Formatting
Developers using the Sovereign SDK do not interact with bytes directly. They interact with typed structures. The SDK performs the canonicalization at the last possible millisecond before hashing. 
*   **Verification:** When an SDK receives a block from the Relay, it MUST re-canonicalize the bytes before calculating the CID. If the received bytes were not canonical (e.g., keys out of order), the block is rejected as "Malformed," even if the signature is valid.

***

**Architect’s Note:** *Canonicalization is the invisible glue of the permanent web. If we get this wrong, the 'Universal Graph' becomes a fragmented mess of operating system bugs. We choose DAG-CBOR because it is the industry standard for verifiable graphs (IPLD). It’s pakka.*
