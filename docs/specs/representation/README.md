---
title: "Data Representation Specification"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-02-23
---

# Data Representation Specification

## 1. Introduction
This document describes the Akshara Representation layer, which defines the physical bitstream standards for all content in a decentralized web. 

The primary goal of this layer is to provide **Bit-Identical Permanence**. Every resource in Akshara is represented by a unique, opaque identifier derived from its content, ensuring that truth is independent of its location or transport medium.

## 2. The Address Model
The fundamental unit of the representation layer is the **`Address`**.

*   **Opaque Envelopes:** Pointers are treated as opaque types (`Address`, `BlockId`, `ManifestId`) to hide the underlying hashing and transport physics from the application logic.
*   **Standards Compatibility:** To ensure interoperability with the global content-addressed ecosystem, Akshara addresses are implemented using the **CIDv1 standard**.
*   **Type-Safety at the Bit-Level:** Akshara utilizes Multicodecs within the address to prevent type-confusion attacks between metadata (Manifests) and data (Blocks).

## 3. Representation Components
The lifecycle of an Akshara resource is defined by two technical components:

1.  **[Encoding](encoding.md) (The Bitstream):** The mandate for **Canonical DAG-CBOR** to ensure deterministic, bit-identical serialization of all structures.
2.  **[Identifiers](identifiers.md) (The Pointers):** The technical specification of how an `Address` is derived and the multicodecs used for structural type-safety.

## 4. Representational Lifecycle
`Input Data` -> `Canonical Encoding` -> `Content Hash` -> `Address`

---

**Summary:** The representation layer ensures that the physical bitstream of an Akshara resource is stable, verifiable, and opaque to the infrastructure that hosts it.
