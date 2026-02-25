---
title: "Identifier Specification"
subtitle: "Opaque Addressing and Type-Safety in Akshara"
version: "0.1.0-alpha"
status: "Proposed"
date: 2026-02-23
---

# Identifier Specification

## 1. Introduction
This document defines the technical structure and verification rules for identifiers within the Akshara ecosystem. All data units are addressed by their cryptographic content, enabling location-independence and immutable references.

## 2. The Address Model
Akshara utilizes a hierarchical set of opaque types to manage pointers. This model ensures that application logic remains decoupled from the underlying hashing and transport physics.

### 2.1 Address (Universal Pointer)
The **`Address`** is the fundamental unit of identification. It represents a unique, bit-verifiable pointer to any resource in the Akshara universe.

### 2.2 Refined Identifiers (Semantic Type-Safety)
To prevent type-confusion attacks at the architectural level, Akshara defines two specialized refinements of the `Address`:

*   **`BlockId`**: An identifier guaranteed to point to an encrypted data block.
*   **`ManifestId`**: An identifier guaranteed to point to a signed graph manifest.

## 3. Physical Implementation (CIDv1)
To ensure interoperability with the global content-addressed ecosystem, Akshara identifiers follow the **CIDv1** (Content Identifier version 1) standard.

### 3.1 Binary Layout
An Akshara `Address` is composed of the following components:
`[Version] [Multicodec] [Multihash]`

*   **Version:** `0x01` (CIDv1).
*   **Multihash Algorithm:** `0x12` (SHA2-256).
*   **Multihash Length:** `0x20` (32 bytes).

### 3.2 Multicodec Registry
Structural type-safety is enforced via the **Multicodec** field. Akshara mandates the following dedicated tags:

| Identifier Type | Multicodec (Hex) | Multicodec (Semantic) |
| :--- | :--- | :--- |
| **`BlockId`** | `0x50` | `identity` (Sovereign Block Base) |
| **`ManifestId`** | `0x51` | `dag-pb` (Sovereign Manifest Base) |

## 4. Verification Invariants
The `Auditor` and `Reconciler` MUST enforce the following integrity rules during any representation-layer operation:

1.  **Codec Enforcement:** Any operation expecting a `BlockId` MUST reject an address with a codec other than `0x50`. Any operation expecting a `ManifestId` MUST reject an address with a codec other than `0x51`.
2.  **Bitstream Verification:** The address MUST be re-derived from the payload bytes using SHA2-256 before the payload is accepted into the local store.
3.  **Fortress Rule (Opaqueness):** Higher-level modules (SDK, Application) MUST NOT attempt to parse or interpret the internal components of an `Address`. It must be treated as an atomic, immutable token.

## 5. Representation
For human-readable contexts (logs, CLI, debugging), the binary CID MUST be encoded using **Base32** (Multibase prefix `b`). 

*   *Example Format:* `bafy...`
