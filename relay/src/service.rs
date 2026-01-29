use crate::mapping::StatusWrapper;
use crate::sovereign_relay::v1::discovery_service_server::DiscoveryService;
use crate::sovereign_relay::v1::sync_service_server::SyncService;
use crate::sovereign_relay::v1::*;
use async_stream::try_stream;
use sovereign_core::graph::DocId;
use sovereign_core::store::GraphStore;
use sovereign_core::store::InMemoryStore;
use sovereign_core::sync::{SyncEngine, SyncRequest as CoreSyncRequest};
use std::convert::TryInto;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

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
        let req = request.into_inner();

        // 1. Map Inputs
        let doc_uuid = Uuid::parse_str(&req.graph_id)
            .map_err(|_| Status::invalid_argument("Invalid graph_id format"))?;
        let doc_id = DocId(doc_uuid);

        let heads = req
            .heads
            .into_iter()
            .map(|h| h.try_into().map_err(|e: StatusWrapper| e.0))
            .collect::<Result<Vec<_>, _>>()?;

        // 2. Logic: SyncEngine
        // Note: SyncEngine takes a Store reference. Since our Store is Arc<InMemoryStore>,
        // we can dereference it. SyncEngine is transient.
        let engine = SyncEngine::new(self.store.as_ref());
        let local_heads = self
            .store
            .get_heads(&doc_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        // Note: CoreSyncRequest needs a constructor or public fields.
        // Currently it has new(heads).
        let core_req = CoreSyncRequest::new(heads);

        let diff = engine
            .calculate_response(&core_req, &local_heads)
            .map_err(|e| Status::internal(e.to_string()))?;

        // 3. Stream Response
        let store = self.store.clone();
        // Move lists into stream
        let missing_manifests = diff.missing_manifests().to_vec();
        let missing_blocks = diff.missing_blocks().to_vec();

        let output_stream = try_stream! {
            // A. Stream Manifests
            for m_id in missing_manifests {
                let manifest = store
                    .get_manifest(&m_id)
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::internal("Missing manifest content"))?;

                yield SyncResponseItem {
                    item: Some(sync_response_item::Item::Manifest(manifest.into())),
                };
            }

            // B. Stream Blocks
            for b_id in missing_blocks {
                let block = store
                    .get_block(&b_id)
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::internal("Missing block content"))?;

                yield SyncResponseItem {
                    item: Some(sync_response_item::Item::Block(block.into())),
                };
            }
        };

        Ok(Response::new(Box::pin(output_stream)))
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
        request: Request<PushLockboxRequest>,
    ) -> Result<Response<PushLockboxResponse>, Status> {
        let req = request.into_inner();

        // 1. Map Inputs
        let doc_id = req
            .graph_id
            .parse::<DocId>()
            .map_err(|_| Status::invalid_argument("Invalid graph_id format"))?;

        let recipient_key = req
            .recipient_key
            .ok_or_else(|| Status::invalid_argument("Missing recipient_key"))?
            .try_into()
            .map_err(|e: StatusWrapper| e.0)?;

        let lockbox = req
            .lockbox
            .ok_or_else(|| Status::invalid_argument("Missing lockbox"))?
            .try_into()
            .map_err(|e: StatusWrapper| e.0)?;

        // 2. Persist
        let mut store = self.store.as_ref().clone();

        store
            .put_lockbox(doc_id, &recipient_key, &lockbox)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(PushLockboxResponse { success: true }))
    }
}
