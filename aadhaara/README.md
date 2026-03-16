# Akshara Aadhaara (v0.1.0-alpha.1)

The imperishable mathematical and cryptographic foundation of the Akshara protocol. **ಅಕ್ಷರ-ಆಧಾರ** (Akshara-Aadhaara) provides the supporting vessel for content-addressed graphs, causal identity, and symmetric synchronization.

## Known Issues (Pre-Release)

| Issue | Severity | Planned |
|-------|----------|---------|
| `BlockContent` in public API | Medium | v0.2 |
| 12-word mnemonic acceptance | High | v0.2 |
| Ghost authority (full history walk) | Critical | v0.2 |
| Identity clustering | Critical | v0.3 |

## Architecture

The foundation is built on three sacred pillars:

1. **Sovereignty:** Authority is derived from personal cryptographic seeds (BIP-39).
2. **Permanence:** Data is bit-identical across architectures (DAG-CBOR).
3. **Integrity:** All state transitions are audited for causality (IdentityGraph).

## Usage Story

### 1. Initialize Identity

Everything starts with your 24-word recovery phrase.

```rust
use akshara_aadhaara::SecretIdentity;

let mnemonic = SecretIdentity::generate_mnemonic()?;
let alice = SecretIdentity::from_mnemonic(&mnemonic, "passphrase")?;
```

### 2. Create a Document Graph

Derive an isolated key for your project and create your first block.

```rust
let graph_id = GraphId::new();
let graph_key = alice.derive_graph_key(&graph_id)?;

let block = Block::new(
    b"Hello Akshara".to_vec(),
    "document".into(),
    vec![], // No parents
    &graph_key,
    &alice
).await?;
```

### 3. Snapshot with a Manifest

Bind your content to your identity history using an anchor.

```rust
let manifest = Manifest::new(
    graph_id,
    block.id(),
    vec![], // No parent manifests
    alice_identity_genesis_id,
    &alice
);
```

### 4. Symmetric Synchronization

Meet a peer and converge your realities in a single turn.

```rust
let reconciler = Reconciler::new(&store, alice_master_pubkey);
let comparison = reconciler.reconcile(&remote_heads, &local_heads).await?;

// Ingest peer's surplus into local store
let report = reconciler.converge(&comparison.peer_surplus, &mut local_store).await?;
println!("Synced {} blocks", report.blocks_synced);
```

## Security Invariants

- **Master Key Binding:** Genesis manifests must be signed by the identity's Master Root Key.
- **Causal Verification:** No block is accepted unless its author was unrevoked at the moment of the identity anchor.
- **Fortress Rule:** Internal library types (CID, Ed25519) are strictly encapsulated within opaque identifiers.
