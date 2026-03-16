# ಅಕ್ಷರ (Akshara): The Imperishable Web

**Encrypted collaboration where the server can't read your data.**

*If the math is healthy, the human is safe.*

---

## Here's the Thing

**The web was built on trust. That's a problem.**

Whether it's a cloud giant, a SaaS startup, or a private server—whoever hosts your data can usually read it. For most apps? Fine. But for **healthcare**, **legal**, and **corporate governance**, "trusting the landlord" is a structural failure.

**Akshara sidesteps the whole problem.**

We break data into blocks, encrypt them, and sign them on your device. The data leaves your device already encrypted. The hosting provider can't read it. Can't tell who you're working with. Can't leak what they never had access to.

> **We don't ask you to trust the host. The host doesn't matter.**

---

## How It Works

Data is decomposed into encrypted blocks. Each block is signed. Blocks are linked into a graph.

**The result:** Every edit is tracked. Every change is signed. Merging happens on your device—not on a server.

---

## Files vs. Graphs

Akshara uses Graphs, not files.

A Graph is a collection of encrypted blocks that share a permission boundary. One contract. One patient record. One project.

**In a Graph:**
- Every edit is tracked and signed
- Merge conflicts are visible branches (not errors)
- Your device reconciles semantically (no server deciding)
- History is a permanent, signed Merkle-DAG

---

## How It Works

### 1. Satyate (ಸತ್ಯತೆ — Integrity)
**The math proves it.** Every piece of data is identified by its hash (CIDv1). Your device checks the math. You never have to "trust" that the sender gave you the right bytes.

### 2. Aadhaara (ಆಧಾರ — Foundation)
**The Relay is blind.** It hosts encrypted blocks identified only by anonymous **Lakshanas**. It doesn't know what's in the box, who wrote it, or who else has a key.

### 3. Akshara (ಅಕ್ಷರ — Imperishable)
**Data outlives the host.** Because data is named by what it *is* (content-addressed), not where it *lives*, it's location-independent. It survives provider bankruptcy. Hardware death. Even obsolescence.

---

## Who is this for?

- **Architects** designing local-first systems that need to work offline.
- **CTOs** handling high-secrecy data (PHI, Legal, Gov) who want to eliminate subpoena risk.
- **Developers** tired of building the same "Login with Google" and "Forgot Password" flows.

**This is NOT for:** Simple chat apps, public social networks, or projects where the server needs to process or "AI-analyze" user data.

---

## Why Akshara?

| Feature | Akshara | The Rest (Signal, IPFS, Proton) |
| :--- | :--- | :--- |
| **Blind Foundation** | ✅ Relay can't cluster your projects | ❌ Host can usually link your metadata |
| **24-Word Recovery** | ✅ Full state restoration from seed | ❌ Centralized recovery or device-locked |
| **Device Revocation** | ✅ Kill a lost phone's access instantly | ❌ Often requires "Resetting" everything |
| **Block-Level Merge** | ✅ Real-time, multi-user merging | ❌ Binary sync or server-side merge |
| **Signed History** | ✅ Every edit has a permanent signature | ❌ Proprietary or "Cloud-only" history |

---

## For Developers

### What Works Now (`aadhaara`)

The hard part works. BIP-39 identity. XChaCha20-Poly1305 encryption. Merkle-DAG operations. It's technical, but it's done.

**See:** [aadhaara README](./aadhaara/README.md) for examples.

### What's Coming (v0.2 SDK)

We're building an API that feels natural. Master seed stays offline. Daily work uses hardware-bound credentials (FaceID, TouchID).

```rust
// 1. Initialize from the device's Secure Enclave
let client = AksharaClient::init_from_enclave().await?;

// 2. Open a document via its anonymous Lakshana
let mut contract = client.open_graph(contract_lakshana).await?;

// 3. Edit naturally. The SDK handles the Merkle-tree and signing.
contract.commit("/clauses/1.1", b"The parties agree...").await?;

// 4. Sync is a conversation between peers
contract.sync(contract_lakshana).await?;
```

---

## ⚠️ Security Notice

**This is alpha. It will break. Don't use it in production.**

Seriously. Get a security audit first.

**The Tech:**
- **Cipher:** XChaCha20-Poly1305 (AEAD)
- **Signatures:** Ed25519
- **Key Exchange:** X25519
- **Identity:** BIP-39 + SLIP-0010

---

## License
Apache 2.0 / MIT

---

**Architect's Note:** *We're not building another cloud service. We're building a digital sanctuary for human agency. If the math is healthy, the human is safe.*

---
*ಅಕ್ಷರ (Akshara)* means "The Imperishable" in Kannada. Data that survives infrastructure.
