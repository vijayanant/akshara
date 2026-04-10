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
//!     .with_ephemeral_vault()
//!     .with_in_memory_storage();
//!
//! let client = Client::init(config).await?;
//!
//! // Create a graph
//! let notes = client.create_graph().await?;
//!
//! // Write data
//! notes.insert("meeting-notes", b"Today we discussed...").await?;
//!
//! // Seal (commits staged operations to the Merkle-DAG)
//! notes.seal().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Core Concepts
//!
//! - **Client**: Entry point, manages identity, vault, and storage
//! - **Graph**: Handle to a single graph for read/write operations
//! - **Staging**: Operations are buffered and coalesced before flushing
//! - **Flushing**: Commits staged operations to the Merkle-DAG via a manifest
//!
//! For the full API specification, see `docs/specs/api/`.

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
pub use client::{Client, GraphSummary};
pub use config::{ClientConfig, StorageConfig};
pub use error::Error;
pub use graph::{Graph, SyncReport};
pub use ordering::{FractionalIndex, midpoint, parse_index};
pub use staging::{StagedOperation, StagingStore};
pub use store::InMemoryStore;
pub use sync::SyncTransport;
pub use vault::Vault;

// Re-export commonly used aadhaara types
pub use akshara_aadhaara::{GraphId, GraphKey, Lakshana, SecretIdentity};
