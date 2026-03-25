//! The Akshara API — Developer-facing interface for building applications on Akshara.
//!
//! This crate provides a high-level API that abstracts the cryptographic and protocol
//! complexity of [`akshara-aadhaara`] into a simple, ergonomic interface.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use akshara::{Client, ClientConfig};
//!
//! # async fn example() -> Result<(), akshara::Error> {
//! // Initialize the client with ephemeral vault (for testing)
//! let config = ClientConfig::new()
//!     .with_ephemeral_vault();
//!
//! let client = Client::init(config).await?;
//!
//! // Create a graph
//! let notes = client.create_graph("my-notes").await?;
//!
//! // Write data
//! notes.insert("meeting-notes", b"Today we discussed...").await?;
//!
//! // Seal and sync
//! notes.seal().await?;
//! client.sync().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Core Concepts
//!
//! - **Client**: Entry point, manages identity, vault, and storage
//! - **Graph**: Handle to a single graph for read/write operations
//! - **Staging**: Operations are buffered and coalesced before sealing
//! - **Sealing**: Commits staged operations to the Merkle-DAG
//!
//! For more details, see the [API specification](https://github.com/vijayanant/akshara/tree/main/docs/akshara).

pub mod client;
pub mod config;
pub mod error;
pub mod graph;
pub mod ordering;
pub mod staging;
pub mod store;
pub mod sync;
pub mod vault;

// Re-export main types for convenience
pub use client::Client;
pub use config::ClientConfig;
pub use error::Error;
pub use graph::{Graph, SealReport, SyncReport};
pub use ordering::{FractionalIndex, midpoint};
pub use staging::{StagedOperation, StagingStore};
pub use store::InMemoryStore;
pub use sync::{Conflict, MergeStrategy, SyncTransport};
pub use vault::{Vault, VaultConfig};

// Re-export commonly used aadhaara types
pub use akshara_aadhaara::{GraphId, GraphKey, SecretIdentity};
