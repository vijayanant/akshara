---
title: "Key Derivation Specification"
subtitle: "BIP-39 and SLIP-0010 Implementation in Akshara"
version: "0.1.0-alpha.2"
status: "Accepted"
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
Keys derived from this branch possess "Executive Authority." They are assigned to hardware or specific roles.

*   **Graph-Isolated Signing (Shadow Identities):** To prevent the Relay from clustering different graphs belonging to the same device, an Executive MUST NOT sign manifests using this long-term key. 
*   **Shadow Derivation:** For a specific graph, the device derives a **Shadow Signing Key**:
    `Shadow_Key = HMAC-SHA256(Executive_Branch_Key, "akshara.v1.shadow_identity" || GraphId)`

```text
SHADOW IDENTITY RITUAL
──────────────────────
[Master Seed]
      │
      ▼ (SLIP-0010)
[Executive Key (Branch 1)] ──┐
      │                      │ (HMAC-SHA256)
      │                      ├───────────────────► [Shadow Signing Key]
[GraphId (UUID)] ────────────┘                        (Unique per Graph)
                                                      (Visible to Relay)
```

*   **Verification:** The `Auditor` verifies the Shadow Key by performing an HMAC check against the authorized Executive Key registered in the Identity Graph. This allows for total anonymity on the Relay while preserving the ability to revoke the physical device.

### 4.3 Branch 2: Secret (Symmetric Keys)
**Path:** `m / 44' / 999' / 0' / 2' / <resource_index>' / <version_index>' /`
This branch is used to derive 256-bit symmetric encryption keys (AES-GCM) for encrypted data blocks.
*   **Resource Index:** A unique deterministic index for each graph.
*   **Version Index:** Incremented during key rotation events to maintain forward secrecy.

### 4.4 Branch 3: Handshake (Pre-Keys)
**Path:** `m / 44' / 999' / 0' / 3' / <credential_index>' / <prekey_index>' /`
This branch is used to derive one-time-use X25519 encryption keys (**Pre-Keys**) for asynchronous sharing.
*   **Pre-Key Bundle:** A collection of these ephemeral keys is signed by the Tier 3 Executive Key and stored on the Relay to facilitate "Offline Handshakes."
*   **Depletion Rule:** A credential SHOULD monitor the remaining pre-key count on the Relay and MUST replenish the bundle when the buffer falls below a threshold (e.g., 20%).
*   **Forward Secrecy:** Once a Pre-Key is consumed for a handshake, its private key MUST be purged from local storage, ensuring that a future device compromise cannot decrypt past sharing events.

### 4.5 Branch 4: Internal Vault (Keyring)
**Path:** `m / 44' / 999' / 0' / 4' / <keyring_version>' /`
This branch is used to derive a **Shared Keyring Secret** used by all authorized credentials belonging to an identity.
*   **Purpose:** Encrypting the Graph Keys within the Resource Index to ensure cross-device synchronization.
*   **Rotation:** This secret MUST be rotated (by incrementing `<keyring_version>'`) following the revocation of any authorized credential to maintain forward secrecy.

### 4.6 Branch 5: Discovery (Anonymous Metadata)
**Path:** `m / 44' / 999' / 0' / 5' / <discovery_index>' /`
This branch is used to derive **Discovery Master Keys** for anonymous graph discovery.
*   **Privacy:** These keys serve as the HMAC secret for Discovery IDs, ensuring the Master Seed is never used directly for network-facing identifiers.

## 5. Security Invariants

| Invariant | Requirement |
|-----------|-------------|
| **One-Way Derivation** | MUST be mathematically impossible to derive parent key from child |
| **Branch Isolation** | Compromise of Branch 1 key MUST NOT reveal Branch 0 or Master |
| **Static Seeds** | Master Seed MUST be zeroized after derivation |
| **Branch Storage** | Each branch key MUST be stored separately for independent revocation |
| **Seed Never Stored** | The mnemonic/seed MUST NEVER be stored - only derived branch keys |

## 5.1. Key Storage Requirements

After derivation from the master seed, branch keys are stored for daily use:

| Key | Storage Location | Reason |
|-----|-----------------|--------|
| **Mnemonic (24 words)** | Never stored | User recovery only |
| **Seed (64 bytes)** | Never stored | Zeroized after derivation |
| **Branch 0-5 keys** | OS Keychain / Secure Enclave | Daily operations |
| **GraphKeys** | Derived on-demand | Per-graph isolation |

**Storage Format:** Each branch is stored as a 64-byte blob (32-byte signing key + 32-byte encryption key), encoded as CBOR or JSON for keychain storage.

**Compartmentalization:** Branches MUST be stored in separate keychain entries to enable independent revocation. A single keychain dump should not reveal all branches.

---

## 6. Algorithms

### 6.1. Mnemonic to Seed

```
Input:  mnemonic (24 words), passphrase (optional string)
Output: seed (64 bytes)

1. Normalize: mnemonic = trim(mnemonic).to_lowercase()
2. Salt = "mnemonic" || passphrase
3. seed = PBKDF2-HMAC-SHA512(
       password = mnemonic (UTF-8 NFKD normalized),
       salt = Salt,
       iterations = 2048
   )
4. Return seed
```

### 6.2. SLIP-0010 Derivation

```
Input:  seed (64 bytes), path (string e.g., "m/44'/999'/0'/0'/")
Output: SigningKey (Ed25519)

1. IL, IR = HMAC-SHA512(key = "ed25519 seed", data = 0x00 || seed)
2. K = IL (left 32 bytes)
3. C = IR (right 32 bytes)
4. For each segment i in path (skip "m"):
   a. index = parse(segment) + 0x80000000  // Hardened only
   b. data = 0x00 || K || index (big-endian)
   c. IL, IR = HMAC-SHA512(key = C, data = data)
   d. K = IL
   e. C = IR
5. Return SigningKey::from_bytes(K)
```

---

## 7. Test Vectors

### Test Vector 1: Standard Mnemonic (No Passphrase)

| Field | Value |
|-------|-------|
| **Mnemonic** | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art` |
| **Passphrase** | (empty) |
| **Seed** | `bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8` |
| **Master Key (m)** | Ed25519 key derived from seed |

### Test Vector 2: With Passphrase

| Field | Value |
|-------|-------|
| **Mnemonic** | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art` |
| **Passphrase** | `TREZOR` |
| **Seed** | Different from Test Vector 1 (passphrase changes seed) |

### Test Vector 3: Branch Derivation

| Field | Value |
|-------|-------|
| **Mnemonic** | (same as Test Vector 1) |
| **Passphrase** | (empty) |
| **Path** | `m/44'/999'/0'/0'/` (Legislator) |
| **Derived Key** | Ed25519 signing key for authorizing devices |

### Test Vector 4: Graph Key Derivation

| Field | Value |
|-------|-------|
| **Mnemonic** | (same as Test Vector 1) |
| **Graph ID** | `550e8400-e29b-41d4-a716-446655440000` (example UUID) |
| **Derivation** | `GraphKey = HMAC-SHA256(MasterSeed, "akshara.v1.graph_key" || GraphID)` |
| **Result** | 32-byte symmetric key for encrypting graph content |

---

## 8. Security Considerations

### What Can Go Wrong

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Weak RNG** | Predictable mnemonics | Use `OsRng` or hardware RNG |
| **Passphrase leakage** | Seed compromise | Store passphrase separately from mnemonic |
| **Key derivation side-channel** | Timing attacks | Use constant-time HMAC implementations |
| **Memory leakage** | Seed exposed in RAM | Zeroize immediately after derivation |

### Implementation Notes

1. **Normalization is critical:** The BIP-39 library is unforgiving. Implementations MUST normalize mnemonics (trim whitespace, lowercase) before derivation.

2. **Hardened derivation only:** Ed25519 does not support safe unhardened derivation. All Akshara paths use hardened indices (`'` suffix).

3. **256-bit entropy mandatory:** 12-word mnemonics (128-bit) are NOT acceptable for Akshara compliance.

---

## 9. References

- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [SLIP-0010: Universal private key derivation from master private key](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [PBKDF2 Specification (RFC 8018)](https://datatracker.ietf.org/doc/html/rfc8018)
