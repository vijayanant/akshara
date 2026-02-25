---
title: "Key Derivation Specification"
subtitle: "BIP-39 and SLIP-0010 Implementation in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Key Derivation Specification

## 1. Entropy Source
Akshara identities are rooted in 256 bits of cryptographically secure randomness.

*   **Mnemonic Standard:** BIP-39.
*   **Word Count:** 24 words.
*   **Security Level:** 256-bit (Akshara Standard).
*   **Checksum:** 8 bits derived from the SHA-256 hash of the entropy.

## 2. Seed Generation
The mnemonic phrase is converted into a 512-bit (64-byte) seed using PBKDF2-HMAC-SHA512.

*   **Password:** The UTF-8 NFKD normalized mnemonic phrase.
*   **Salt:** The string `"mnemonic"` concatenated with an optional user-provided passphrase.
*   **Iterations:** 2048.

## 3. Hierarchical Deterministic Derivation
Akshara utilizes **SLIP-0010** for deterministic derivation of Ed25519 and X25519 key pairs. To maintain total branch isolation and prevent parent-to-child public key leakage, **Hardened Derivation** is mandated for all levels of the tree.

### 3.1 The Akshara Root Path
Following the BIP-44 pattern, the root of the Akshara identity is established at:
`m / 44' / 999' / 0' /`

*   `44'`: Purpose (Standard HD Wallet).
*   `999'`: Coin Type (Akshara Protocol).
*   `0'`: Primary Identity Account.

## 4. Functional Branches
Authority is delegated through specific sub-trees under the Akshara Root Path.

### 4.1 Branch 0: Management (Legislator)
**Path:** `m / 44' / 999' / 0' / 0' /`
Keys derived from this branch possess "Legislative Authority." They are used exclusively to sign updates to the Identity Graph, such as authorizing or revoking Tier 3 (Executive) keys.

### 4.2 Branch 1: Executive (Credential)
**Path:** `m / 44' / 999' / 0' / 1' / <credential_index>' /`
Keys derived from this branch possess "Executive Authority." They are assigned to hardware or specific roles and used to sign graph manifests and facilitate peer-to-peer synchronization.

### 4.3 Branch 2: Secret (Symmetric Keys)
**Path:** `m / 44' / 999' / 0' / 2' / <resource_index>' / <version_index>' /`
This branch is used to derive 256-bit symmetric encryption keys (AES-GCM) for encrypted data blocks.
*   **Resource Index:** A unique deterministic index for each graph.
*   **Version Index:** Incremented during key rotation events to maintain forward secrecy.

### 4.4 Branch 3: Handshake (Pre-Keys)
**Path:** `m / 44' / 999' / 0' / 3' / <credential_index>' / <prekey_index>' /`
This branch is used to derive one-time-use X25519 encryption keys (**Pre-Keys**) for asynchronous sharing.
*   **Pre-Key Bundle:** A collection of these ephemeral keys is signed by the Tier 3 Executive Key and stored on the Relay to facilitate "Offline Handshakes."
*   **Depletion Rule:** A credential SHOULD monitor the remaining pre-key count on the Relay and MUST replenish the bundle (by incrementing `<credential_index>'` and resetting `<prekey_index>'`) when the buffer falls below a threshold (e.g., 20%).

### 4.5 Branch 4: Internal Vault (Keyring)
**Path:** `m / 44' / 999' / 0' / 4' / <keyring_version>' /`
This branch is used to derive a **Shared Keyring Secret** used by all authorized credentials belonging to an identity.
*   **Purpose:** Encrypting the Graph Keys within the Resource Index to ensure cross-device synchronization.
*   **Rotation:** This secret MUST be rotated (by incrementing `<keyring_version>'`) following the revocation of any authorized credential to maintain forward secrecy.
*   **Forward Secrecy:** Once a Pre-Key is consumed for a handshake, its private key is purged, ensuring that a future device compromise cannot decrypt past sharing events.

## 5. Security Invariants
*   **One-Way Derivation:** It MUST be mathematically impossible to derive a parent private key from a child private key.
*   **Branch Isolation:** Compromise of a key at path `m/.../1'/0'` MUST NOT provide any information regarding the key at `m/.../0'/` or `m/.../1'/1'`.
*   **Static Seeds:** The Master Seed MUST be stored in `zeroize`-protected memory and physically purged from RAM immediately after child derivation is complete.
