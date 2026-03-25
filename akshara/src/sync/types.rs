//! Sync-related types.

use akshara_aadhaara::{GraphId, ManifestId};

/// Represents a sync conflict (concurrent edits to same path).
#[derive(Debug, Clone)]
pub struct Conflict {
    /// The graph where the conflict occurred.
    pub graph_id: GraphId,
    /// The path with conflicting edits.
    pub path: String,
    /// Concurrent manifest heads causing the conflict.
    pub heads: Vec<ManifestId>,
    /// Optional resolution strategy.
    pub strategy: Option<MergeStrategy>,
}

/// Strategy for resolving sync conflicts.
#[derive(Debug, Clone)]
pub enum MergeStrategy {
    /// Keep the manifest with the lexicographically lower CID.
    /// Deterministic, all peers converge to same result.
    KeepLatest,

    /// Keep the local manifest (our version wins).
    /// Opinionated, may diverge across peers.
    KeepMine,

    /// Keep the remote manifest (their version wins).
    /// Opinionated, useful for "server is authoritative" scenarios.
    KeepTheirs,

    /// Manual resolution via custom resolver.
    Manual {
        /// Resolver identifier (application-specific).
        resolver_name: String,
    },
}

impl Default for MergeStrategy {
    fn default() -> Self {
        Self::KeepLatest
    }
}
