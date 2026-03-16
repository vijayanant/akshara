---
title: "ADR: Tiered Identity and Hierarchical Authority"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-02-23
---

# Architectural Decision Record: Tiered Identity

## 1. Context
Initial drafts of the original identity model were inconsistent regarding entropy requirements (12 vs 24 words) and utilized a "Flat" key structure where a single Ed25519 key was used for all administrative and data-signing tasks.
 This created a single point of failure: if a device was stolen, the entire identity was compromised without a clear mathematical path for recovery or isolated revocation. Furthermore, the model did not account for how shared project keys would be synchronized across a user's multiple authorized devices.

## 2. Decision
We have decided to adopt a **Five-Branch Hierarchical Deterministic (HD) Model** based on **BIP-39** and **SLIP-0010**.

### 2.1 256-bit Entropy Standard
We mandate the use of **24-word mnemonics** (256 bits of entropy) for all Akshara identities.
*   **Rationale:** 128-bit security (12 words) is insufficient for "Akshara" (Imperishable) data intended to survive for decades. 256-bit security provides the necessary margin against future brute-force threats.

### 2.2 Functional Branching (Separation of Concerns)
We utilize hardened derivation paths to isolate levels of authority and data access:
*   **Tier 1 (Master):** The root seed ($m$), never stored on networked hardware.
*   **Branch 0 (Legislator):** Path `m/0'/`. Used exclusively for identity management (Add/Revoke).
*   **Branch 1 (Executive):** Path `m/1'/`. Used for day-to-day data signatures on graph manifests.
*   **Branch 2 (Secret):** Path `m/2'/`. Used to derive symmetric encryption keys for user-authored graphs.
*   **Branch 4 (Keyring):** Path `m/4'/`. Used to derive a **Shared Keyring Secret** for cross-device access to shared resources.

## 3. Rationale
*   **Privilege Isolation:** By using **Hardened Derivation**, we ensure that a compromised Executive key (Tier 3) cannot mathematically derive or influence Legislator or Master keys.
*   **Causal Recovery:** This hierarchy allows the Legislator key to sign "Timeline Corrections" that invalidate malicious signatures without requiring a change to the user's root seed.
*   **The Hive Invariant:** To enable seamless multi-device access to shared resources, all authorized credentials belonging to an identity must share access to the **Keyring Secret**. This secret allows a laptop to store a shared graph key in the Identity Graph that the phone can immediately decrypt and use.
*   **Stateless State:** By using deterministic paths for encryption keys (Branch 2), we eliminate the need for the user to "back up" keys for their own graphs; they are re-calculable from the 24 words.

## 4. Alternatives Considered
*   **Flat Keys (Status Quo):** Rejected. Too vulnerable to hardware theft and lacks recovery ergonomics.
*   **Multi-Signature Management:** Deferred. While more secure, it imposes a significant UX burden. The HD hierarchy provides a better balance of "Individual Agency" and "Security."

## 5. Consequences
*   **Breaking Change:** Existing 12-word identities are deprecated and MUST be migrated to the 24-word standard.
*   **Auditor Complexity:** The `Auditor` component must now support path-aware verification to enforce these tiers.
*   **Metadata Privacy:** The use of `MasterSeed` for the `DiscoveryId` ensures that Alice's identity remains invisible to the Relay.
