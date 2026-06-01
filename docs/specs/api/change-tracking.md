# Spec 9: Collaborative Change Tracking & Diffing

**Status:** Draft — For Review  
**Date:** 2026-06-01  
**Derived from:** [API Design Principles](../blueprint/sdk/api-design-principles.md), [Spec 2: Typed Documents](./typed-documents.md), [Spec 8: Audit](./audit.md)  
**Cross-references:** [Client & Graph](./client-and-graph.md), [Conflicts](./conflicts.md), [Errors](./errors.md)

---

## Scope

This spec defines:
- **Change Tracking**: Resolving and traversing the historical edit lineage of a specific path (a document section, paragraph, or structured field) back to its origin block.
- **Metadata-Preserving Fields**: Rich types (`CollaborativeText`, `ParagraphNode`, `DocField<T>`) that retain block CIDs, author public keys, and signatures on deserialization instead of discarding them.
- **Document-Level Diffing**: Using the Lowest Common Ancestor (LCA) manifest to generate a structured, key-attributed diff between two document checkpoints or divergent heads.
- **Collaborative Sign-off**: Sealing a merged document state with multiple parent manifests, representing a cryptographic joint agreement.

---

## 1. Metadata-Preserving API Types

To prevent the erasure of cryptographic metadata during deserialization, the SDK provides wrappers for structured fields and collaborative text.

### 1.1 `DocField<T>`

Wraps standard primitive fields in structured documents to retain their edit origin.

```rust
pub struct DocField<T> {
    /// The deserialized value of the field.
    pub value: T,

    /// The Block ID (CID) of the block storing this value.
    pub block_id: BlockId,

    /// The public key of the author who committed this value.
    pub author: SigningPublicKey,

    /// The signature of the author attesting to this value.
    pub signature: Signature,
}
```

### 1.2 `CollaborativeText`

A rich text structure optimized for collaborative editing. It splits content into ordered paragraphs or sentences while preserving metadata for each unit.

```rust
pub struct CollaborativeText {
    /// The ordered list of text paragraph/sentence nodes.
    pub paragraphs: Vec<ParagraphNode>,
}

pub struct ParagraphNode {
    /// The fractional index key determining this node's order.
    pub key: FractionalIndex,

    /// The text content of the paragraph.
    pub text: String,

    /// The Block ID (CID) of the block storing this paragraph.
    pub block_id: BlockId,

    /// The public key of the author who wrote this paragraph.
    pub author: SigningPublicKey,

    /// The signature of the author.
    pub signature: Signature,
}
```

---

## 2. Lineage & History Queries

The SDK allows developers to walk backward through block parent pointers to reconstruct the timeline of edits for a specific path.

### 2.1 `Graph::get_history`

```rust
impl Graph {
    /// Retrieve the complete change history for a specific path or field.
    ///
    /// This walks the content-addressed DAG parents backward from the current
    /// version, collecting the value, timestamp, and author signature for each revision.
    pub async fn get_history(&self, path: &str) -> Result<Vec<RevisionEntry>, Error>;
}
```

### 2.2 `RevisionEntry`

```rust
pub struct RevisionEntry {
    /// The value at this point in history.
    pub value: Vec<u8>,

    /// The Block ID (CID) of this revision.
    pub block_id: BlockId,

    /// The manifest containing the transaction.
    pub manifest_id: ManifestId,

    /// The author's signature and public key.
    pub author: SigningPublicKey,
    pub signature: Signature,

    /// The timestamp of the manifest (0 for rebirth manifests).
    pub timestamp: DateTime<Utc>,
}
```

### 2.3 Traversal Algorithm
1. Locate the current block CID at the target path using path resolution from the latest manifest.
2. Loop until the block ID matches `BlockId::null()` or has no parents:
   - Read the block from the local store.
   - Decrypt the block using the graph key.
   - Record the author, signature, decrypted bytes, and enclosing manifest information.
   - Follow the parent links (`Block.parents`) backward. (For linear edits, `parents` contains exactly one block CID; for resolved merges, it contains multiple parents).

---

## 3. Attributed Document Diffing

When multiple collaborators edit a document (online or offline), the SDK uses Merkle Index diffs and Lowest Common Ancestor (LCA) manifests to generate change-tracked diffs.

```
                    ┌──► [Lawyer A: Manifest A (Head 1)]
                    │
[Manifest LCA] ─────┤
                    │
                    └──► [Lawyer B: Manifest B (Head 2)]
```

### 3.1 `Graph::diff_document`

```rust
impl Graph {
    /// Compares a document at two manifest checkpoints and returns a key-attributed diff.
    ///
    /// If no manifests are provided, it defaults to comparing the active head
    /// against the Lowest Common Ancestor (LCA) of all current divergent heads.
    pub async fn diff_document<D: AksharaDocument>(
        &self,
        path: &str,
        base: Option<ManifestId>,
        target: Option<ManifestId>,
    ) -> Result<DocumentDiff, Error>;
}
```

### 3.2 `DocumentDiff`

```rust
pub struct DocumentDiff {
    /// The document path.
    pub path: String,

    /// The base manifest compared.
    pub base_manifest: ManifestId,

    /// The target manifest compared.
    pub target_manifest: ManifestId,

    /// The Lowest Common Ancestor manifest found.
    pub lca_manifest: ManifestId,

    /// Structural field modifications.
    pub field_changes: HashMap<String, FieldChange>,

    /// Paragraph modifications (for CollaborativeText fields).
    pub text_changes: HashMap<String, Vec<TextChange>>,
}

pub enum FieldChange {
    Inserted {
        new_value: Vec<u8>,
        author: SigningPublicKey,
    },
    Modified {
        old_value: Vec<u8>,
        new_value: Vec<u8>,
        author: SigningPublicKey,
        prev_author: SigningPublicKey,
    },
    Deleted {
        old_value: Vec<u8>,
        author: SigningPublicKey, // Person who deleted it (author of the deleting manifest)
    },
}

pub enum TextChange {
    Inserted {
        key: FractionalIndex,
        text: String,
        author: SigningPublicKey,
    },
    Modified {
        key: FractionalIndex,
        old_text: String,
        new_text: String,
        author: SigningPublicKey,
    },
    Deleted {
        key: FractionalIndex,
        old_text: String,
        author: SigningPublicKey,
    },
}
```

---

## 4. Collaborative Sign-off Flow

To complete a workflow (e.g. finalizing a legal contract), all parties must agree and sign a merged manifest that points back to all parent heads.

### 4.1 Joint Signing Lifecycle

```
[Lawyer A Head] ───┐
                    ├───► [Signed Merge Manifest (Joint Agreement)]
[Lawyer B Head] ───┘
```

1. **Conflict Discovery**: After sync, the graph enters a divergent state. The app uses `diff_document` to present Lawyers A and B with highlighted differences.
2. **Review & Reconcile**: The lawyers select the winning changes or edit a new draft.
3. **Merge Commit Creation**:
   - The developer calls `resolve_conflict()`, saving the agreed document.
   - The SDK writes the merged blocks.
   - The SDK creates a manifest pointing to both `Lawyer A Head` and `Lawyer B Head` as parents.
4. **Co-Signing**:
   - Each lawyer signs the resulting merge manifest with their Executive Signing key.
   - The relay distributes the signed manifests.
   - Once all required signatures are present in the manifest history, the document is verifiably and non-refutably finalized.

---

## 5. Design Decisions

### 5.1 Why not use standard JSON diffs?
Standard JSON diffing has no concept of cryptographic identity or lineage. It can tell you *what* changed, but not *who* changed it or *which* specific block they signed. By leveraging Merkle Index and block parent structures, Akshara links diffs directly to Ed25519 signatures and BIP-32 derivation paths.

### 5.2 Attributing deletions
When a field is deleted in a manifest, the data block itself is missing from the new state. The diff engine attributes the deletion to the **signer of the manifest** that removed the field, ensuring there are no anonymous deletions in the history log.

---

## 6. Cross-Reference Index

| Concept | Defined here | Used in |
|---|---|---|
| `DocField<T>` / `CollaborativeText` | §1 | [Typed Documents](./typed-documents.md) |
| `get_history()` / `RevisionEntry` | §2 | [Client & Graph](./client-and-graph.md) |
| `diff_document()` / `DocumentDiff` | §3 | [Conflicts](./conflicts.md), [Reactive](./reactive.md) |
| Collaborative signing flow | §4 | [Access Control](./access-control.md) |

---

**Certified by:**  
*The Akshara Council of One*
