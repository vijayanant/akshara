---
title: "Sharing and Access Delegation Specification"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Sharing and Access Delegation Specification

## 1. Introduction
This document describes the Akshara Sharing protocol, which defines the rules for delegating access to encrypted resources across separate identities.

In Akshara, sharing is treated strictly as a **Secure Key Transport** problem. Because the infrastructure (Relay) is trust-agnostic and blind, access cannot be granted through server-side permissions. Instead, access is delegated by securely transporting symmetric encryption keys from an authorized credential to a new collaborator using pairwise asymmetric encryption.

## 2. Delegation Model
Akshara utilizes a **User-Centric Delegation** model based on the following components:

1.  **Secure Envelopes ([Lockboxes](lockboxes.md)):** The primary unit of access transport. A Lockbox is a symmetric key sealed with the recipient's public encryption key using a Diffie-Hellman handshake.
2.  **Asynchronous Mailbox ([Pre-Keys](prekeys.md)):** A mechanism for sharing access with offline users. It utilizes pools of signed, one-time-use ephemeral keys to facilitate handshakes at rest.

## 3. Core Properties
*   **Zero-Trust Transport:** The Relay facilitates the movement of Lockboxes but mathematically lacks the credentials required to open them. The trust boundary remains strictly at the edge.
*   **Forward Secrecy:** Asynchronous handshakes utilize one-time Pre-Keys. A compromise of an identity's long-term keys in the future cannot be used to decrypt past sharing events.
*   **Symmetric-to-Asymmetric Bridge:** The protocol provides the formal transition between the shared symmetric security of a graph and the individual asymmetric security of a user's identity.

## 4. Documentation Structure
*   [**Lockboxes**](lockboxes.md): Specification of X25519 (ECDH) handshakes and the AES-GCM envelope structure.
*   [**Pre-Keys**](prekeys.md): Specification of the Asynchronous Handshake and Pre-Key Bundle lifecycle.
