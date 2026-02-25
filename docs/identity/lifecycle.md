---
title: "Identity Lifecycle Specification"
subtitle: "Protocols for Authorization, Revocation, and Recovery in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Identity Lifecycle Specification

## 1. Introduction
This document defines the formal procedures for managing an Akshara identity throughout its operational lifespan. These rituals ensure the secure delegation of authority from the Master Root to specific hardware credentials and provide the mechanism for recovery in the event of compromise or loss.

## 2. Ritual of Birth (Genesis)
Identity creation is the process of generating the 256-bit entropy seed and establishing the first Legislator Manifest.

1.  **Entropy Generation:** The client generates 256 bits of randomness and encodes it into a 24-word BIP-39 mnemonic.
2.  **Master Derivation:** The client derives the Master Private Key ($m$) and the Legislator Key ($m/44'/999'/0'/0'$).
3.  **Genesis Manifest:** The client signs a manifest with an `identity_anchor` of `0x00...00` using the Legislator Key. This manifest establishes the root of the Identity Graph.

## 3. Ritual of Authorization (Credential Onboarding)
Authorization delegates "Executive Authority" to a specific piece of hardware or role.

1.  **Request:** The new credential generates a temporary X25519 encryption key ($P_{temp}$) and an Ed25519 signing key ($P_{dev}$).
2.  **Legislative Signing:** The user utilizes their Legislator Key ($m/0'$) to sign an **Authorization Block** containing:
    *   The Credential Public Key ($P_{dev}$).
    *   An encrypted **Keybox** (sealed with $P_{temp}$) containing the **Shared Keyring Secret** (Branch 4).
    *   The assigned derivation path (e.g., `m/1'/0'`).
    *   Metadata (Label, timestamp).
3.  **Graph Update:** The Authorization Block is added to the Identity Graph at `/credentials/<P_hex>`.

## 4. Ritual of Revocation (Compromise Recovery)
Revocation terminates the authority of a compromised or lost credential.

1.  **Legislative Decision:** The user utilizes their Legislator Key ($m/0'$) to sign a **Revocation Block** targeting the compromised public key ($P_{bad}$).
2.  **Graph Update:** The Revocation Block is added to the Identity Graph at `/revocations/<P_bad>`. 
3.  **Causal Termination:** The `Auditor` now rejects any manifest signed by $P_{bad}$ if that manifest is anchored to this or any future Identity Manifest.

## 5. Ritual of Correction (The Timeline Force-Push)
Timeline Correction is the procedure for erasing the history created by an unauthorized actor before their credential was revoked.

1.  **Conflict Identification:** The user identifies the last known-good Identity Manifest CID ($A_{good}$) before the compromise occurred.
2.  **The Correction Manifest:** The user utilizes their Legislator Key ($m/0'$) to sign a new Identity Manifest ($M_{fix}$).
3.  **Parentage:** $M_{fix}$ lists $A_{good}$ as its only parent, explicitly bypassing and "pruning" the malicious branch signed by the unauthorized actor.
4.  **Precedence Enforcement:** The `Auditor` observes the two competing branches. Because the correction branch is signed by the **Legislator Key**, it takes absolute precedence over any branch signed only by an **Executive Key**. The malicious branch becomes a "Dead Fork."

## 6. Ritual of State Restoration (Full Recovery)
State Restoration is the reconstruction of an identity on new hardware after total device loss.

1.  **Mnemonic Input:** The user provides the 24-word mnemonic.
2.  **Seed Restoration:** The client reconstructs the Master Seed and the Legislator Key ($m/0'$).
3.  **Discovery:** The client uses the Master Seed to derive the stable `DiscoveryId` and locates the latest Identity Manifest on the network.
4.  **Verification:** The client verifies the Identity Graph using the Legislator Key.
5.  **New Foundation:** The client initiates the Ritual of Authorization to establish the new hardware as a valid Executive node.

## 7. Accountability Invariants
*   **Bit-Permanence:** While a Timeline Correction causes the network to ignore a malicious branch, the branch remains physically stored on Bob's node if he synced it during the "Thief's Window." 
*   **Fork Detection:** A Correction event is detectable as a "Non-Fast-Forward" update. Peers record these events as part of the identity's reputational history.
