---
title: "Pre-Key Specification"
subtitle: "Asynchronous Handshakes and Offline Sharing"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Pre-Key Specification

## 1. Introduction
The Pre-Key protocol enables **Asynchronous Sharing**, allowing an authorized credential to delegate access to a recipient who is currently offline. It removes the requirement for both parties to be simultaneously present on the network to perform a cryptographic handshake.

## 2. The Pre-Key Bundle
Every Akshara identity maintains a pool of signed, one-time-use encryption keys—**Pre-Keys**—stored on the Relay. 

### 2.1 Bundle Composition
A Pre-Key Bundle consists of:
*   **Static Identity Key ($P_{stat}$)**: The long-lived public encryption key of the recipient's identity.
*   **Ephemeral Pre-Keys ($P_{e1}, P_{e2}, ...$ )**: A collection of X25519 public keys derived from the Handshake Branch (Branch 3) of the identity tree.
*   **Bundle Signature**: A signature over the entire collection, produced by the recipient's Tier 3 Executive Key to prevent Relay-side tampering.

## 3. Asynchronous Handshake Protocol
When an initiator (Bob) wants to share a resource with an offline recipient (Alice):

1.  **Fetch:** Bob queries the Relay for Alice's current Pre-Key Bundle.
2.  **Verify:** Bob verifies the Bundle Signature against Alice's Identity Graph.
3.  **Selection:** Bob's client selects ONE ephemeral Pre-Key ($P_{ex}$) from the bundle.
4.  **Handshake:** Bob performs ECDH using his own ephemeral secret and the selected $P_{ex}$ to derive the `HandshakeKey`.
5.  **Seal:** Bob creates a Lockbox using this key and pushes it to Alice's inbox.
6.  **Consume:** The Relay atomically removes $P_{ex}$ from Alice's bundle to prevent re-use.

## 4. Key Recovery (Alice's Wakeup)
When Alice returns online:
1.  **Retrieval:** She downloads the Lockbox from her inbox.
2.  **Identification:** The Lockbox contains the index of the Pre-Key ($P_{ex}$) used.
3.  **Re-derivation:** Alice utilizes her Master Seed to re-derive the private key corresponding to $P_{ex}$ from her Branch 3 sub-tree.
4.  **Open:** She extracts the `GraphKey` and joins the resource.

## 5. Security Invariants
*   **Forward Secrecy:** Once a Pre-Key's private key is used by the recipient, it MUST be purged from local memory. This ensures that a future device compromise cannot be used to decrypt past sharing handshakes.
*   **One-Time Guarantee:** The Relay MUST NOT vend the same Pre-Key to multiple initiators. If a bundle is exhausted, sharing attempts MUST fail until the recipient replenishes the buffer.
