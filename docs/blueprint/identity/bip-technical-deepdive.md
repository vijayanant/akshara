# Technical Deep-Dive: BIP-39 & SLIP-0010 in Sovereign

This note documents the technical mechanics of our "Tier 1" identity implementation. We have adopted Bitcoin-grade standards to ensure that a Sovereign Identity is portable, durable, and mathematically recoverable.

## 1. BIP-39: The Human-to-Binary Bridge
BIP-39 (Bitcoin Improvement Proposal 39) defines how to turn high-entropy randomness into a human-readable mnemonic phrase.

### Entropy to Mnemonic
*   **The Root:** We use **256 bits** of random entropy.
*   **The Checksum:** We take the first 8 bits of the SHA-256 hash of the entropy and append them to the end. Total: 264 bits.
*   **The Words:** We split these 264 bits into 24 chunks of 11 bits each. Each 11-bit chunk corresponds to an index (0-2047) in the standard English wordlist.
*   **Rigor:** We chose 24 words over 12 because 256-bit security is the "Akshara" (Permanent) standard for long-term data preservation.

### Mnemonic to Seed (PBKDF2)
The mnemonic is converted into a 512-bit (64-byte) seed using the **PBKDF2-HMAC-SHA512** algorithm.
*   **The Password:** The mnemonic phrase itself.
*   **The Salt:** The string `"mnemonic"` + an optional user-provided **Passphrase**.
*   **Iterations:** 2048 rounds of stretching.
*   **Result:** A 64-byte binary seed that is impossible to reverse-engineer back to the words.

## 2. SLIP-0010: Deterministic Ed25519
While most of the crypto world uses BIP-32 for hierarchical derivation, BIP-32 is designed for the `secp256k1` curve (Bitcoin/Ethereum). For **Ed25519** (which we use for its speed and security), we must use **SLIP-0010**.

### The Master Node
We take our 64-byte seed and run it through `HMAC-SHA512` with the key `"ed25519 seed"`.
*   **Left 32 bytes:** The Master Secret Key.
*   **Right 32 bytes:** The Chain Code (used for further branching).

### Hardened Derivation
Ed25519 does not support "Normal" (unhardened) child derivation without security risks. Therefore, Sovereign **only** uses Hardened Derivation.
*   **The Path:** `m / 44' / 999' / 0' / 0' / 0'`
    *   `44'`: BIP-44 Purpose.
    *   `999'`: Sovereign's Registered Coin Type (simulated).
    *   `0'`: The specific "Sovereign Identity" account.

## 3. The Normalization Gate
One of our key discoveries was that the BIP-39 library is unforgiving. If a user types " Abandon" (with a space) or "ABANDON" (all caps), the derivation fails.

We implemented a **Normalization Gate** in `SecretIdentity::from_mnemonic`:
```rust
let normalized = phrase.trim().to_lowercase();
```
This ensures that the "Physics" of the recovery is robust against "Human" input variations.

## 4. Why this is "Fortress" Security
*   **Offline Rebirth:** You don't need to check a server to see if your key is correct. If the 24 words are right, the keys are right.
*   **Brute Force Resistance:** With 256 bits of entropy, even a supercomputer running until the heat death of the universe cannot guess your phrase.
*   **Passphrase Protection:** The optional passphrase acts as a "25th word." Even if someone steals your 24-word paper, they cannot derive your keys without the passphrase.

## Implementation Details
*   **Crate:** `bip39` version 2.0.0.
*   **Entropy Source:** `rand::rngs::OsRng` (System-level entropy).
*   **Zeroization:** All secret keys are stored in `zeroize`-protected memory to prevent leakages in RAM.
