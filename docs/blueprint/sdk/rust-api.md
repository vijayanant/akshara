# SDK Rust API Specification

This document defines the high-level Rust interface for `sovereign-sdk`. This is the canonical "Spec" we use to implement the platform's Layer 1 logic.

---

## 1. The Entry Point: `SovereignClient`
The `SovereignClient` manages the user's Tier 1 Identity, their Keyring (Dashboard), and the global connections to the frontier.

```rust
pub struct SovereignClient {
    pub identity: IdentityManager,
    pub keyring: KeyringManager,
    // Internal: Store, Network, etc.
}

impl SovereignClient {
    /// Bootstraps the client from a 24-word mnemonic (256-bit seed).
    /// This performs the "Rebirth Flow" if the local DB is empty.
    pub async fn init(mnemonic: &str, config: Config) -> Result<Self, SdkError>;

    /// Returns a list of all Graphs the user has access to.
    /// Uses Blind Discovery to find new projects on the Relay.
    pub async fn list_graphs(&self) -> Result<Vec<GraphSummary>, SdkError>;

    /// Opens a specific Graph for reading and writing.
    pub async fn open_graph(&self, id: GraphId) -> Result<GraphHandle, SdkError>;

    /// Creates a brand new Graph.
    pub async fn create_graph(&self, model: GovernanceModel) -> Result<GraphHandle, SdkError>;
}
```

## 2. Working with Data: `GraphHandle`
The `GraphHandle` is the primary tool for application developers. It encapsulates the `GraphKey` and manages the Merkle Index.

```rust
pub struct GraphHandle {
    pub id: GraphId,
    // Internal: Decrypted GraphKey, Local Store reference
}

impl GraphHandle {
    /// Returns the current "Heads" (most recent Manifests) of the graph.
    pub async fn heads(&self) -> Result<Vec<Manifest>, SdkError>;

    /// Reads a value from a specific path using recursive Merkle Index resolution.
    /// Returns the decrypted Plaintext bytes.
    pub async fn read_path(&self, path: &str) -> Result<Vec<u8>, SdkError>;

    /// Commits new data to a specific path.
    /// This creates new Data Blocks and updates the hierarchical Merkle Index.
    pub async fn commit(&mut self, path: &str, content: Vec<u8>) -> Result<CID, SdkError>;

    /// Synchronizes this specific graph with the Relay.
    /// Triggers the incremental Streaming SyncPipeline.
    pub async fn sync(&self) -> Result<(), SdkError>;

    /// Shares this graph with another user by creating a Lockbox.
    pub async fn share_with(&mut self, user_pub_key: SigningPublicKey) -> Result<(), SdkError>;
}
```

## 3. Turning Blocks into State: `Projector`
The SDK provides a standard way to turn a "Mess of Blocks" into a "Usable State."

```rust
pub trait Projector: Send + Sync {
    type State;

    /// The "Fold" function. Takes the current state and a new block, 
    /// returning the updated state.
    fn project(&self, current: Self::State, block: &Block) -> Self::State;
}

// Example usage in an app:
// let chat_messages: Vec<Message> = graph.project(ChatProjector::default()).await?;
```

---

## 4. Architectural Constraints (The "No Black Box" Rules)
1.  **Async by Default:** All IO-bound operations (Read, Commit, Sync) are `async`.
2.  **Cloneable Handles:** `GraphHandle` and `SovereignClient` use `Arc` internally and are cheap to clone.
3.  **Atomic Commits:** A `commit` call is atomic locally. It is only pushed to the Relay when `sync()` is called (or if background sync is enabled).
4.  **Strict Verification:** The `read_path` and `heads` methods perform full integrity and authority audits (including Codec and Cycle checks) before returning data.

***

**Architect’s Note:** *This API is designed for 'Local-First' efficiency. By separating 'Commit' (writing to disk) from 'Sync' (writing to the world), we give the app developer total control over the user experience. No more 'Saving...' spinners.*