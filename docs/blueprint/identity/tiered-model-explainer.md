# Technical Explainer: The 3-Tier Identity Model

This note documents our hierarchical identity system. In the Sovereign Web, identity is not an account; it is a mathematical consequence of 24 words (*Akshara*).

## 1. Tier 1: The Master Seed (The Root)
Everything begins with a 24-word BIP-39 mnemonic phrase.

**The Math:**
*   **Entropy:** 256 bits (32 bytes).
*   **Derivation:** We use **SLIP-0010** to derive a master Ed25519 seed. 
*   **Result:** A single root key that represents the human being.

**Rigor discovered:** Standard wordlists are case-sensitive and intolerant of whitespace. We implemented a strict **Normalization Gate** (`trim().to_lowercase()`) to ensure user errors don't cause recovery failures.

## 2. Tier 2: The Identity Graph (The Person)
A single key is too fragile for daily use. Instead, we use the Master Seed to sign an **Identity Graph**.

**The Structure:**
*   It is a private, encrypted Sovereign Graph.
*   Path `/devices`: Maps friendly names (e.g., "laptop_1") to specific device public keys.
*   Path `/keys`: Stores ephemeral authority mappings.

**Why this matters:** If you lose your phone, you don't change your 24 words. You just publish a new version of your Identity Graph that revokes the phone's key. This is **Portable Authority**.

## 3. Tier 3: The Keyrings (The Access)
We never use the same key for two different documents. Instead, we use **Domain-Isolated Derivation**.

**The Logic:**
`GraphKey = HMAC(Master_Signing_Key, "sovereign.v1.graph_key" + Graph_ID)`

*   **Deterministic:** Re-derived on the fly from the 24 words + the document's UUID.
*   **Isolated:** A leak in Graph A provides zero information about Graph B.
*   **Zero-Storage:** We never save GraphKeys to disk. They are "Akshara"—always reborn when the human provides their seed.

## Summary for Implementation
*   **Security:** 256-bit entropy is mandatory.
*   **Recovery:** The `test_full_identity_rebirth_recovery` proves that a user can lose their device and still decrypt every document using only their words.
*   **Privacy:** Relays see CIDs and Ciphertext but have no knowledge of the derivation path or the Identity Graph structure.
