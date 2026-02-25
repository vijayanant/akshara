---
title: "Lockbox Specification"
subtitle: "Pairwise Asymmetric Enveloping in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Lockbox Specification

## 1. Introduction
A **Lockbox** is the atomic unit of access transport in Akshara. It allows an authorized credential to securely send a symmetric `GraphKey` to a new recipient over an untrusted network.

## 2. Cryptographic Handshake
Lockboxes are constructed using an **X25519** (Diffie-Hellman) key agreement to establish a shared secret between the sender and the recipient.

### 2.1 Sender Side (Creation)
1.  **Ephemeral Key:** The sender generates a temporary X25519 key pair ($P_{eph}$, $S_{temp}$).
2.  **Agreement:** The sender performs ECDH using $S_{temp}$ and the recipient's long-term **Public Encryption Key** ($P_{rec}$) to derive the `SharedSecret`.
3.  **KDF:** The `SharedSecret` is processed through a Key Derivation Function (HKDF-SHA256) to yield a 256-bit `HandshakeKey`.

### 2.2 Recipient Side (Extraction)
1.  **Agreement:** The recipient performs ECDH using their **Private Encryption Key** ($S_{rec}$) and the sender's $P_{eph}$ (included in the lockbox) to reconstruct the same `SharedSecret`.
2.  **KDF:** The recipient applies the same HKDF to recover the `HandshakeKey`.

## 3. The Envelope Structure
The payload is protected using **AES-256-GCM** authenticated encryption.

### 3.1 Binary Layout
A Lockbox is encoded in DAG-CBOR and consists of:
*   **`ephemeral_pk`**: The $P_{eph}$ used by the sender.
*   **`nonce`**: A unique 12-byte initialization vector.
*   **`ciphertext`**: The encrypted payload.
*   **`tag`**: The 16-byte authentication tag.

## 4. Payload Schema
The decrypted `ciphertext` contains a CBOR map with the following fields:
*   **`graph_id`**: The 128-bit identifier of the resource.
*   **`graph_key`**: The 256-bit symmetric key for the graph.
*   **`iteration`**: The key version index (for rekeying events).

## 5. Security Invariants
*   **Pairwise Isolation:** Every lockbox is unique to a specific sender-recipient pair. 
*   **Authenticated Delivery:** The recipient MUST verify the `tag` before attempting to use the `graph_key`. 
*   **Ephemeral Purge:** The sender MUST purge $S_{temp}$ immediately after the ciphertext is produced to maintain forward secrecy.
