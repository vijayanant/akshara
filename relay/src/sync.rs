use crate::error::RelayError;
use crate::mapping::StatusWrapper;
use crate::sovereign_relay::v1::sync_service_server::SyncService;
use crate::sovereign_relay::v1::*;
use async_stream::try_stream;
use sovereign_core::graph::{Block, GraphId, Manifest};
use sovereign_core::store::GraphStore;
use sovereign_core::store::InMemoryStore;
use sovereign_core::sync::{SyncEngine, SyncRequest as CoreSyncRequest};
use std::convert::TryInto;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct RelaySyncService {
    pub store: Arc<InMemoryStore>,
}

#[tonic::async_trait]
impl SyncService for RelaySyncService {
    type SyncStream = Pin<Box<dyn Stream<Item = Result<SyncResponseItem, Status>> + Send>>;

    async fn sync(
        &self,
        request: Request<SyncRequest>,
    ) -> Result<Response<Self::SyncStream>, Status> {
        let req = request.into_inner();

        let graph_id: GraphId = req
            .graph_id
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid graph_id format"))?;

        let heads = req
            .heads
            .into_iter()
            .map(|h| h.try_into().map_err(|e: StatusWrapper| e.0))
            .collect::<Result<Vec<_>, _>>()?;

        let engine = SyncEngine::new(self.store.as_ref());
        let local_heads = self
            .store
            .get_heads(&graph_id)
            .map_err(RelayError::from)
            .map_err(Status::from)?;

        let core_req = CoreSyncRequest::new(heads);

        let diff = engine
            .calculate_response(&core_req, &local_heads)
            .map_err(RelayError::from)
            .map_err(Status::from)?;

        let store = self.store.clone();
        let missing_manifests = diff.missing_manifests().to_vec();
        let missing_blocks = diff.missing_blocks().to_vec();

        let output_stream = try_stream! {
            for m_id in missing_manifests {
                let manifest = store
                    .get_manifest(&m_id)
                    .map_err(RelayError::from)?
                    .ok_or_else(|| Status::internal("Missing manifest content"))?;

                yield SyncResponseItem {
                    item: Some(sync_response_item::Item::Manifest(manifest.into())),
                };
            }

            for b_id in missing_blocks {
                let block = store
                    .get_block(&b_id)
                    .map_err(RelayError::from)?
                    .ok_or_else(|| Status::internal("Missing block content"))?;

                yield SyncResponseItem {
                    item: Some(sync_response_item::Item::Block(block.into())),
                };
            }
        };

        Ok(Response::new(Box::pin(output_stream)))
    }

    async fn push(&self, request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        let req = request.into_inner();

        let mut blocks = Vec::new();
        for proto_block in req.blocks {
            let block: Block = proto_block.try_into().map_err(|e: StatusWrapper| e.0)?;
            block
                .verify_integrity()
                .map_err(RelayError::from)
                .map_err(Status::from)?;
            blocks.push(block);
        }

        let mut manifests = Vec::new();
        for proto_manifest in req.manifests {
            let manifest: Manifest = proto_manifest.try_into().map_err(|e: StatusWrapper| e.0)?;
            manifest
                .verify_integrity()
                .map_err(RelayError::from)
                .map_err(Status::from)?;
            manifests.push(manifest);
        }

        let mut store = self.store.as_ref().clone();

        for block in blocks {
            store
                .put_block(&block)
                .map_err(RelayError::from)
                .map_err(Status::from)?;
        }

        for manifest in manifests {
            store
                .put_manifest(&manifest)
                .map_err(RelayError::from)
                .map_err(Status::from)?;
        }

        Ok(Response::new(PushResponse { success: true }))
    }
}
