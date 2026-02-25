---
title: "Authority Verification Specification"
subtitle: "Identity Graph Auditing and Causal Trust in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Authority Verification Specification

## 1. Introduction
This document defines the algorithm for verifying the cryptographic authority of a signer within the Akshara ecosystem. Unlike static PKI systems, Akshara uses a temporal, content-addressed **Identity Graph** to prove the "Right to Sign" at any given point in history.

## 2. The Identity Graph Structure
The Identity Graph is a Merkle-DAG representing the authorization history of an identity. It utilizes a standard directory-like hierarchy encoded in DAG-CBOR:

*   **`/credentials/<public_key_hex>`:** Contains authorization blocks for Tier 3 (Executive) keys.
*   **`/revocations/<public_key_hex>`:** Contains tombstone blocks for revoked keys.
*   **`/capabilities/<public_key_hex>`:** Defines scoped path permissions for a specific key.

## 3. Authority Resolution (The Causal Walk)
To verify a signature on a graph manifest, the `Auditor` must perform a causal walk of the Identity Graph starting from the `identity_anchor` provided in the manifest.

### 3.1 Verification Algorithm
Given a signature $S$, a public key $P$, and an identity anchor $A$:

1.  **Integrity Check:** The Auditor verifies that signature $S$ is mathematically valid for public key $P$ over the manifest ID.
2.  **Anchor Resolution:** The Auditor fetches the Identity Manifest identified by CID $A$.
3.  **Existence Proof:** The Auditor resolves the path `/credentials/<P_hex>` within the graph at anchor $A$.
    *   If the path does not exist, authority is REJECTED.
4.  **Revocation Check:** The Auditor resolves the path `/revocations/<P_hex>` within the graph at anchor $A$.
    *   If a revocation block exists, authority is REJECTED.
5.  **Causal Validity:** If the key exists and is not revoked at anchor $A$, the signature is accepted as valid for that specific historical context.

## 4. Conflict Resolution (Tie-Breaking)
The Identity Graph is a Directed Acyclic Graph (DAG). In scenarios where concurrent updates occur (e.g., two authorized devices modify the graph simultaneously), multiple "heads" may exist.

*   **Deterministic Tie-Breaking:** In the event of a causal fork, the branch with the **numerically lower CID** takes precedence. 
*   **Convergent Truth:** This ensures that all peers independently arrive at the same authoritative state of the identity without requiring a central coordinator.

## 5. Master Key Binding (Genesis Rule)
The root of trust for any Identity Graph is the **Master Root** key derived from the Tier 1 seed.

*   **Null Anchor:** An identity anchor of `0x00...00` identifies a "Genesis Manifest."
*   **Binding Law:** A Genesis Manifest is ONLY valid if signed by a key derived from the **Legislator Branch** (`m/44'/999'/0'/0'/`) of the identity.
*   This ensures that no third party can "re-found" an existing graph by spoofing a new genesis point.

## 5. Path-to-Purpose Enforcement
The `Auditor` enforces strict functional isolation based on the BIP-32 derivation path of the signer:

| Action | Required Derivation Path |
| :--- | :--- |
| **Authorize Credential** | `m/44'/999'/0'/0'/` (Legislator) |
| **Revoke Credential** | `m/44'/999'/0'/0'/` (Legislator) |
| **Sign Graph Manifest** | `m/44'/999'/0'/1'/...` (Executive) |
| **Update Capability** | `m/44'/999'/0'/0'/` (Legislator) |

## 6. Audit Invariants
*   **Causal Precedence (Merkle-Time):** The Auditor MUST ignore the `created_at` timestamp for security-critical decisions. Validity is determined solely by Merkle-linkage. A revocation event is only "after" an authorization if the revocation manifest includes the authorization manifest (or its descendants) in its causal history. This protects the system against "Byzantine Clock" attacks.
*   **Temporal Immutability:** An authority proof is only valid for the specific CID of the identity anchor.
 A key authorized at Anchor $A$ is not automatically authorized at Anchor $B$.
*   **Strict Revocation:** A revocation block is a "Permanent Tombstone." Once a key is recorded in `/revocations/`, it can never be re-authorized within that identity sub-tree.
*   **Atomic Handshake:** The Relay MUST implement an atomic "Fetch-and-Remove" operation when vending Pre-Keys to ensure that a one-time key is never vended to multiple initiators (Forward Secrecy).
