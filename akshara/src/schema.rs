//! Typed Document Facade for Akshara.

pub mod collaborative_text;
pub mod document;
pub mod field;
pub mod lazy;

pub use collaborative_text::{CollaborativeText, ParagraphNode};
pub use document::{AksharaDocument, BlockMode, DocumentSchema, FieldDescriptor};
pub use field::DocField;
pub use lazy::LazyField;

// Expose the derive macro re-export
pub use akshara_schema_macros::AksharaDocument;
