# Tiered Identity: The Adhara of Authority

Identity in Sovereign is not an account in a database. It is a **Graph of Authority** owned and controlled by the individual. We use a three-tier model to ensure absolute security and seamless recovery.

---

## 1. Tier 1: The Master Identity (The Seed)
The user's digital existence is anchored in a 256-bit secret, represented as a **BIP-39 Mnemonic** (24 words).
*   **Role:** The Supreme Judge. It is used ONLY to authorize or revoke device keys. 
*   **Safety:** This seed never touches the internet. It lives on a piece of paper or an air-gapped device.
*   **Hardening:** We enforce strict normalization (trimming and lowercasing) to ensure that human input errors do not prevent deterministic recovery.

## 2. Tier 2: The Identity Graph (The Person)
A user's identity is an append-only Merkle Graph of signed authorizations and revocations.
*   **Delegation:** The Master Key signs a **Delegation Block** authorizing a phone or laptop key to sign on its behalf.
*   **Revocation:** If a phone is stolen, the user uses their 24 words to sign a **Revocation Block** in the Identity Graph.
*   **Structure:** We use our Merkle Index structure to organize this graph (e.g., path `/devices/laptop_1`).

## 3. Tier 3: The Keyrings (The Access)
We never use the same key for two different documents. Instead, we use **Domain-Isolated Derivation**.

**The Derivation Math:**
*   **Discovery ID:** `HMAC(Master_Seed, "sovereign.v1.discovery")`. Used to find your Identity Graph on a Relay without revealing your seed.
*   **Graph Key:** `HMAC(Master_Seed, "sovereign.v1.graph_key" + Graph_ID)`. A unique symmetric key for every document.

---

## 4. The Recovery Protocol: The 30-Second Rebirth
This tiered model solves the "Account Recovery" problem without a central server:
1.  **Rebirth:** The user enters 24 words on a new phone. The phone derives the Master Keys.
2.  **Discovery:** The phone re-calculates the **Discovery ID** and finds the user's public Identity Graph on any Relay.
3.  **Restoration:** The phone re-calculates the unique **GraphKeys** for all projects the user belonged to. **Access is restored.**

***

**Architect’s Note:** *This is where we solve the 'Human Paradox' of crypto—being both unhackable and recoverable. By separating the Root from the Activity, we give users a safety net that doesn't rely on a 'Forgot Password' email.*
