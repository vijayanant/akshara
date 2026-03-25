//! Storage backends for Akshara.
//!
//! Re-exports storage from akshara-aadhaara.

pub use akshara_aadhaara::InMemoryStore;

// TODO: Implement SQLite store later
// For now, use InMemoryStore from aadhaara
