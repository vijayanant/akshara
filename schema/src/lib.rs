//! `akshara-schema` — The Typed Document Facade for Sovereign.
//!
//! This crate provides the high-level abstractions for defining structured
//! document patterns and mapping them to the Merkle-DAG physics.

pub mod adapters;
pub mod document;

pub use document::{AksharaDocument, BlockMode, DocumentSchema, FieldDescriptor, LazyField};

/// Export the base error type for use in macro expansion.
pub use akshara_aadhaara::AksharaError;

/// Export the canonical bytes helper for use in macro expansion.
pub use akshara_aadhaara::to_canonical_bytes;

/// The `AksharaDocument` derive macro.
///
/// Automatically generates the `DocumentSchema` and `AksharaDocument` trait
/// implementation for a Rust struct.
///
/// # Example
/// ```rust
/// use akshara_schema::AksharaDocument;
///
/// #[derive(AksharaDocument, serde::Serialize, serde::Deserialize)]
/// struct Note {
///     pub title: String,
///     #[lazy]
///     pub body: String,
/// }
/// ```
#[cfg(feature = "derive")]
pub use akshara_schema_macros::AksharaDocument;

// If the feature is not enabled, we still want to re-export it if available internally
#[cfg(not(feature = "derive"))]
pub use akshara_schema_macros::AksharaDocument;
