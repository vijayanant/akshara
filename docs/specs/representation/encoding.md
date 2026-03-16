---
title: "Encoding Specification"
subtitle: "Canonical Serialization and Representational Strictness"
version: "0.1.0-alpha.2"
status: "Accepted"
date: 2026-02-23
---

# Encoding Specification

## 1. Introduction
This document defines the rules for transforming abstract data structures into the physical bitstreams used by the Akshara protocol. To achieve **Bit-Identical Permanence**, Akshara mandates a single, deterministic representation for every unique state.

## 2. The Standard: DAG-CBOR
Akshara utilizes the **DAG-CBOR** (Concise Binary Object Representation) standard, as defined in RFC 8949 and refined by the IPLD specification. 

### 2.1 Deterministic Constraints
To ensure a 1:1 mapping between data and bytes, the following canonicalization rules MUST be enforced during serialization:

1.  **Map Key Ordering:** Keys within a map MUST be sorted lexicographically based on their encoded binary representation.
2.  **Integer Encoding:** Integers MUST be represented in the smallest possible CBOR encoding (e.g., using 1 byte if the value is < 24).
3.  **No Indefinite Lengths:** Arrays and maps MUST use definite-length encoding. Indefinite-length streams are prohibited.
4.  **No Duplicate Keys:** Maps MUST NOT contain duplicate keys.

## 3. Representational Strictness (Anti-Malleability)
To prevent "Ghost Bit" vulnerabilities where multiple byte streams decode to the same logical object, Akshara decoders MUST operate in **Strict Mode**.

### 3.1 Decoder Invariants
The decoder MUST return an error and reject the bitstream if any of the following are detected:

*   **Non-Minimal Encodings:** Any value (integer, length, or tag) that is not encoded in its smallest possible form.
*   **Out-of-Order Keys:** Any map where keys do not follow the lexicographical sort order.
*   **Type Lenience:** Any mismatch between the Major Type in the bitstream and the type expected by the schema (e.g., accepting a Byte String where a Text String is required).
*   **Extraneous Data:** Any trailing bytes in the stream after the primary object has been fully decoded.

## 4. Logical-to-Physical Mapping
Akshara structures are mapped to CBOR types according to the following table:

| Akshara Logic | CBOR Major Type | Implementation Note |
| :--- | :--- | :--- |
| **Integer (i64/u64)** | `0` / `1` | Minimal representation required. |
| **Byte Array (Bytes)** | `2` (Byte String) | Used for encrypted payloads and raw CIDs. |
| **Text (String)** | `3` (Text String) | Must be valid UTF-8. |
| **Collection (Vec)** | `4` (Array) | Definite-length only. |
| **Record (Struct)** | `5` (Map) | Lexicographical key sorting required. |
| **Identifier (Address)** | `6` (Tag) | CIDv1 objects are encoded as Tag 42 (Binary CID). |

## 5. Implementation Standard
The foundation currently utilizes the `serde_cbor` crate. However, implementations SHOULD migrate to stricter codecs (e.g., `ciborium`) that provide native enforcement of the invariants defined in Section 3 to ensure absolute representational integrity.
