//! Storage backends for Akshara.
//!
//! Re-exports storage from akshara-aadhaara and provides SQLite persistent storage.

pub use akshara_aadhaara::InMemoryStore;

pub mod sqlite;
pub use sqlite::SqliteStore;
