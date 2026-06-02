//! Real in-memory sync transport for local testing and demos.
//!
//! Connects two local InMemoryStores directly to execute functional sync protocols.

use crate::error::{Error, Result};
use crate::sync::SyncTransport;
use akshara_aadhaara::{Delta, GraphStore, Heads, InMemoryStore, ManifestId, Portion, Reconciler};
use futures::{Stream, StreamExt, stream};
use std::pin::Pin;

/// A sync transport that bridges to another in-memory store in the same process.
pub struct LocalMemoryTransport {
    peer_store: InMemoryStore,
}

impl LocalMemoryTransport {
    /// Create a new local memory transport pointing to a peer's store.
    pub fn new(peer_store: InMemoryStore) -> Self {
        Self { peer_store }
    }
}

#[async_trait::async_trait]
impl SyncTransport for LocalMemoryTransport {
    async fn exchange_heads(
        &self,
        graph_id: akshara_aadhaara::GraphId,
        _local_heads: Vec<ManifestId>,
    ) -> Result<Heads> {
        let peer_heads = self
            .peer_store
            .get_heads(&graph_id)
            .await
            .map_err(|e| Error::SyncFailed(format!("Failed to query peer heads: {}", e)))?;
        Ok(Heads::new(graph_id, peer_heads))
    }

    async fn request_portions(
        &self,
        delta: &Delta,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>> {
        let reconciler = Reconciler::new(&self.peer_store);
        let portions = reconciler
            .fulfill(delta)
            .await
            .map_err(|e| Error::SyncFailed(format!("Failed to retrieve portions: {}", e)))?;

        let stream = stream::iter(portions.into_iter().map(Ok));
        Ok(Box::pin(stream))
    }

    async fn push_portions(
        &self,
        mut portions: Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>,
    ) -> Result<()> {
        while let Some(portion_result) = portions.next().await {
            let portion = portion_result?;
            let address = portion.id();
            let data = portion.data();

            // Ingest directly into peer's store
            if address.codec() == akshara_aadhaara::CODEC_AKSHARA_MANIFEST {
                let manifest =
                    akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Manifest>(data)
                        .map_err(|e| {
                            Error::SyncFailed(format!("Failed to decode manifest: {}", e))
                        })?;
                self.peer_store
                    .put_manifest(&manifest)
                    .await
                    .map_err(|e| Error::SyncFailed(format!("Failed to save manifest: {}", e)))?;
            } else {
                let block = akshara_aadhaara::from_canonical_bytes::<akshara_aadhaara::Block>(data)
                    .map_err(|e| Error::SyncFailed(format!("Failed to decode block: {}", e)))?;
                self.peer_store
                    .put_block(&block)
                    .await
                    .map_err(|e| Error::SyncFailed(format!("Failed to save block: {}", e)))?;
            }
        }
        Ok(())
    }
}
