pub mod derivation;
pub mod graph;
pub mod mnemonic;
pub mod paths;
pub mod types;

// --- Public API Exports ---

pub use graph::IdentityGraph;
pub use types::SecretIdentity;

#[cfg(test)]
mod test_identity;

#[cfg(test)]
mod test_identity_graph;

#[cfg(test)]
mod test_identity_protocol;

#[cfg(test)]
mod test_temporal_forgery;

#[cfg(test)]
mod test_authority_edge_cases;
