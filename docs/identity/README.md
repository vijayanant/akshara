---
title: "Identity and Authority Specification"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Identity and Authority Specification

## 1. Introduction
This document describes the Akshara Identity protocol for managing cryptographic authority and key derivation in an asynchronous, multi-device setting.

The protocol is designed to provide a hierarchical root of trust for content-addressed Merkle-DAGs. It enables deterministic recovery of state and verifiable revocation of compromised credentials without relying on a centralized registry or a trusted third party.

## 2. Model
The protocol operates across four distinct levels of authority, separated through **Hardened Derivation** (BIP-32):

1.  **Tier 1: Master Root ($m$):** The ultimate source of trust, derived from a 256-bit entropy seed (BIP-39). It is used to generate the functional branches of the identity.
2.  **Tier 2: Management (Legislator):** A hardened child branch used exclusively for authorizing and revoking Tier 3 credentials within the Identity Graph.
3.  **Tier 3: Executive (Device):** Hardened child branches assigned to specific hardware or roles. These keys sign graph manifests and facilitate data synchronization.
4.  **Tier 4: Resources (Encryption):** Symmetric and asymmetric keys derived for specific resource identifiers, providing cryptographic isolation between disparate graphs.

## 3. Core Properties
*   **Hierarchical Isolation:** Hardened derivation ensures that compromise of an Executive (Tier 3) key does not expose the Master Root (Tier 1) or the Management (Tier 2) credentials.
*   **Causal Authority:** Manifest signatures are verified against a temporal audit of the Identity Graph, ensuring a key was valid at the moment of snapshot creation.
*   **Stateless Recovery:** All resource identifiers and encryption keys are deterministically recoverable from the Tier 1 entropy seed.

## 4. Documentation Structure
The specification is divided into the following technical components:

*   [**Key Derivation**](derivation.md): The BIP-39 and SLIP-0010 implementation details.
*   [**Authority Verification**](authority.md): The logic for the Causal Walk and Identity Graph auditing.
*   [**Credential Lifecycle**](lifecycle.md): Protocols for authorization, revocation, and timeline correction.
*   [**Resource Indexing**](discovery.md): Algorithms for deterministic resource discovery and recovery.
