# Identity Graph: The Timeline of Authority

A Sovereign Identity is not a single key; it is a **Graph of Authority**. It is an append-only log of signed events that define which devices are currently authorized to act on behalf of the user.

---

## 1. The Root Anchor (Tier 1)
Every Identity Graph begins with a **Genesis Block** signed by the user's **Master Key** (derived from their 12 words). This block defines the "Root of Trust" for the entire digital existence.

## 2. Delegation: Empowering the Edge
When a user adds a new device (e.g., a Phone), they use their Master Key (or an authorized device) to sign a **Delegation Block**.
*   **Contents:**
    *   `device_pub_key`: The Ed25519 key of the new device.
    *   `expiration`: A causal timestamp or TTL.
    *   `capabilities`: What the device is allowed to do (e.g., "Full Access" vs. "Read Only").

## 3. Revocation: Silencing the Ghost
If a device is stolen, the user signs a **Revocation Block** in the Identity Graph. 
*   **Effect:** This block effectively kills the device’s authority in causal time. 
*   **Enforcement:** Any SDK receiving a message signed by the stolen device will walk the Identity Graph, see the Revocation, and reject the message.

## 4. Continuity and Conflict
Like any Sovereign Graph, the Identity Graph is a DAG.
*   **Sequential Edits:** Bob authorizes Laptop -> Laptop authorizes Phone. (A chain).
*   **Concurrent Edits:** Bob authorizes Laptop while his Tablet authorizes Phone. (A fork).
*   **Resolution:** Identity forks are resolved using **Deterministic Tie-Breaking** (Lower CID wins). This ensures every peer on earth has the same view of "Who is Bob" at any given moment.

## 5. Metadata Privacy: Blind Identifiers
To prevent the Relay from linking a user's Identity Graph to their real-world name, the Identity ID is a **Blind Hash**:
`Identity_ID = Hash("sovereign.v1.identity" || Master_Public_Key)`

***

**Architect’s Note:** *This is the heart of Tiered Identity. We have moved from a 'Static Key' (which is a single point of failure) to a 'Timeline of Proofs.' It’s the only way to build a system that survives device churn and human error.*
