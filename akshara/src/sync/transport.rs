//! Sync transport abstraction.
//!
//! This module defines the trait for sync transports (relay, P2P, etc.)
//! and provides a mock implementation for testing.

use std::pin::Pin;

use akshara_aadhaara::{Delta, Heads, ManifestId, Portion};
use futures::Stream;

use crate::error::Result;

/// Unique identifier for a sync session.
pub type SessionId = String;

/// Sync transport trait for communicating with relays or peers.
///
/// Implementations handle the network/IPC layer while the sync engine
/// handles the protocol logic.
#[async_trait::async_trait]
pub trait SyncTransport: Send + Sync {
    /// Exchange heads with a remote peer.
    ///
    /// Sends local heads and receives remote heads for the given graph.
    async fn exchange_heads(
        &self,
        graph_id: akshara_aadhaara::GraphId,
        local_heads: Vec<ManifestId>,
    ) -> Result<Heads>;

    /// Request missing portions from a remote peer.
    ///
    /// Returns a stream of portions that fill the gaps identified in the delta.
    async fn request_portions(
        &self,
        delta: &Delta,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>>;

    /// Push portions to a remote peer.
    ///
    /// Used for bidirectional sync where both peers share missing data.
    async fn push_portions(
        &self,
        portions: Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>,
    ) -> Result<()>;
}
