# Design Decision: Tiered Identity & Durable Authority

## Context
Decentralized identity is notoriously difficult to manage. Most systems fail because they are either too complex (PGP) or too fragile (lose your phone, lose your account). We needed a model that was both unhackable and recoverable.

---

## The Decision: Master Root with Delegated Timeline

### 1. Hierarchical Key Derivation (BIP-39 / SLIP-0010)
A Sovereign user's true identity is a 256-bit secret represented as 12 words. All daily keys (Signing, Encryption) are derived from this seed using the **SLIP-0010** standard.
*   **Rationale:** Math is portable. If our software disappears, the user can recover their identity using any standard-compliant tool.

### 2. Decoupled Signing Interface (`SovereignSigner`)
The Core protocol never interacts with private keys directly. It uses a `Signer` trait.
*   **Rationale:** This allows us to support **Hardware Wallets** (HSMs) and Remote Signers where the secret key never touches the user's computer.

### 3. The Identity Graph (Tiered Authority)
Identity is not a static state; it is an append-only timeline.
*   **Tier 1 (Master):** The Root. Signs delegations.
*   **Tier 2 (Device):** The Leaves. Performs daily document signatures.
*   **Tier 3 (Keyring):** The Map. Holds the keys to all the user's graphs.

---

## Consequences
*   **Durable Recovery:** Users can regain access to their entire digital life using only their 12 words.
*   **Granular Revocation:** If a laptop is stolen, the user signs a single block in their Identity Graph to silence that device forever across all docs.
*   **Causal Verification:** To verify a message, the SDK must walk the author's Identity Graph. This adds computational overhead but eliminates the "Stolen Key" disaster.

***

**Architect’s Note:** *This is our 'Adhara' for people. We have separated 'Being' (Root Key) from 'Doing' (Device Key). It’s the only way to build a professional-grade identity system that real humans can actually use.*
