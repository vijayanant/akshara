use crate::mapping::StatusWrapper;
use crate::sovereign_relay::v1::discovery_service_server::DiscoveryService;
use crate::sovereign_relay::v1::sync_service_server::SyncService;
use crate::sovereign_relay::v1::*;
use sovereign_core::store::GraphStore;
use sovereign_core::store::InMemoryStore;
use std::convert::TryInto;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct RelayService {
    store: Arc<InMemoryStore>,
}

impl RelayService {
    pub fn new(store: Arc<InMemoryStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl SyncService for RelayService {
    type SyncStream = Pin<Box<dyn Stream<Item = Result<SyncResponseItem, Status>> + Send>>;

    async fn sync(
        &self,
        request: Request<SyncRequest>,
    ) -> Result<Response<Self::SyncStream>, Status> {
        let _req = request.into_inner();
        Err(Status::unimplemented("Sync not yet implemented"))
    }

    async fn push(&self, _request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        Err(Status::unimplemented("Push not yet implemented"))
    }
}

#[tonic::async_trait]
impl DiscoveryService for RelayService {
    #[allow(clippy::collapsible_if)]
    async fn list_graphs(
        &self,
        request: Request<ListGraphsRequest>,
    ) -> Result<Response<ListGraphsResponse>, Status> {
        let req = request.into_inner();

        let recipient_key_proto = req
            .recipient_key
            .ok_or_else(|| Status::invalid_argument("Missing recipient_key"))?;
        let recipient_key = recipient_key_proto
            .try_into()
            .map_err(|e: StatusWrapper| e.0)?;

        let lockboxes = self
            .store
            .get_lockboxes_for_recipient(&recipient_key)
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut summaries = Vec::new();

        for (doc_id, lockbox) in lockboxes {
            let heads = self
                .store
                .get_heads(&doc_id)
                .map_err(|e| Status::internal(e.to_string()))?;

            let head_id = match heads.first() {
                Some(id) => id,
                None => continue,
            };

            let manifest = match self
                .store
                .get_manifest(head_id)
                .map_err(|e| Status::internal(e.to_string()))?
            {
                Some(m) => m,
                None => continue,
            };

            // Find the metadata block (convention: first active block)
            let meta_block = if let Some(block_id) = manifest.active_blocks().first() {
                self.store
                    .get_block(block_id)
                    .map_err(|e| Status::internal(e.to_string()))?
            } else {
                None
            };

            if let Some(block) = meta_block {
                summaries.push(GraphSummary {
                    graph_id: doc_id.0.to_string(),
                    lockbox: Some(lockbox.into()),
                    head_manifest_id: Some((*head_id).into()),
                    metadata_block: Some(block.into()),
                });
            }
        }

        Ok(Response::new(ListGraphsResponse { summaries }))
    }

    async fn push_lockbox(
        &self,
        _request: Request<PushLockboxRequest>,
    ) -> Result<Response<PushLockboxResponse>, Status> {
        Err(Status::unimplemented("PushLockbox not yet implemented"))
    }
}
