# Technical Explainer: Content Identifiers (CIDs)

This note documents our transition from raw hashes to CIDs and the specific technical traps we found in the Rust implementation. This is the *Adhara* (foundation) for our naming system.

## 1. Why move beyond the Raw Hash?
As discussed in our [Content Addressing vision](../product/vision.md), a raw 32-byte hash is a "Blind Pointer." It tells you the fingerprint but nothing about the context.

**The Problem with Raw Hashes:**
*   **No Algorithm Agility:** If we hardcode SHA-256 and the algorithm is broken, we have to refactor the entire system.
*   **Ambiguity:** A raw hash doesn't tell the system if it points to an encrypted block, a signed manifest, or a structural index.

## 2. Enter the CID (The IPFS Standard)
We adopted the **CIDv1** standard (pioneered by IPFS) because it is a self-describing pointer. It prefixes the hash with metadata.

**Anatomy of a CIDv1:**
`[Version][Multicodec][Multihash_Type][Digest]`

*   **Version:** Always `0x01`.
*   **Multicodec:** The data type (We use `0x50` for Sovereign Blocks, `0x51` for Manifests).
*   **Multihash:** The algorithm (We use `0x12` for SHA2-256).

This turns a "Hash" into a "Typed Pointer."

## 3. The "Permissive Parsing" Discovery
During implementation, we found a critical security discrepancy in the standard Rust `cid` crate.

### The Behavior:
The library's `try_from(&[u8])` implementation is designed for **Streams**. It reads the prefix, sees the length (e.g., 32 bytes), reads exactly that many bytes, and returns `Ok`. 

**The Vulnerability:**
If the input buffer has **extra data** at the end (trailing junk), the library simply ignores it. In Sovereign, we store IDs in fixed-size protobuf fields. If we allow "Dangling Bytes," we open the door to **Metadata Injection**—an attacker could hide malicious tags or extra entropy inside our identifiers.

## 4. The "Pakka" Fix: Strict Ingestion
To ensure the integrity of our IDs, we wrapped the library in a strict ingestor using `io::Cursor`.

```rust
pub fn from_bytes(bytes: &[u8]) -> Result<Self, SovereignError> {
    let mut cursor = std::io::Cursor::new(bytes);
    // 1. Parse the CID from the cursor
    let cid = Cid::read_bytes(&mut cursor)
        .map_err(|_| IntegrityError::MalformedId)?;

    // 2. THE LAW: Ensure the entire buffer was consumed
    if cursor.position() != bytes.len() as u64 {
        return Err(IntegrityError::MalformedId);
    }
    
    // 3. CODEC CHECK: Ensure it matches the expected type (Block vs Manifest)
    if cid.codec() != CODEC_SOVEREIGN_BLOCK {
        return Err(IntegrityError::MalformedId);
    }

    Ok(BlockId(cid))
}
```

## 5. Confidence through Property-Based Testing
To prove this foundation is solid, we moved beyond manual unit tests and used **Property-Based Testing (PBT)** with the `proptest` crate.

*   **Logic:** Generate 1,000+ random byte sequences (shuffled prefixes, truncated digests, random lengths).
*   **Requirement:** The parser must NEVER panic, and it must ONLY return `Ok` if the bytes are a mathematically perfect Sovereign CID.

## Summary for Implementation
*   **Codec 0x50:** Block (Encrypted Leaf).
*   **Codec 0x51:** Manifest (Signed Snapshot).
*   **Strictness:** Always use `BlockId::try_from` or `ManifestId::try_from` rather than the base `Cid` crate directly to ensure no dangling bytes.
