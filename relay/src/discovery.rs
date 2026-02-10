use crate::error::RelayError;
use sovereign_core::graph::GraphId;
use sovereign_core::store::GraphStore;
use sovereign_core::store::InMemoryStore;
use sovereign_wire::mapping::StatusWrapper;
use sovereign_wire::v1::discovery_service_server::DiscoveryService;
use sovereign_wire::v1::*;
use std::convert::TryInto;
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct RelayDiscoveryService {
    pub store: Arc<InMemoryStore>,
}

#[tonic::async_trait]
impl DiscoveryService for RelayDiscoveryService {
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
            .map_err(RelayError::from)
            .map_err(Status::from)?;

        let mut summaries = Vec::new();

        for (doc_id, lockbox) in lockboxes {
            let heads = self
                .store
                .get_heads(&doc_id)
                .map_err(RelayError::from)
                .map_err(Status::from)?;

            let head_id = match heads.first() {
                Some(id) => id,
                None => continue,
            };

            let manifest = match self
                .store
                .get_manifest(head_id)
                .map_err(RelayError::from)
                .map_err(Status::from)?
            {
                Some(m) => m,
                None => continue,
            };

            // In Merkle model, metadata is inside the content_root block.
            // For Discovery summary, we fetch the root block as a hint.
            let root_block = self
                .store
                .get_block(&manifest.content_root())
                .map_err(RelayError::from)
                .map_err(Status::from)?
                .ok_or_else(|| Status::internal("Missing content root block"))?;

            summaries.push(GraphSummary {
                graph_id: doc_id.0.to_string(),
                lockbox: Some(lockbox.into()),
                head_manifest_id: Some((*head_id).into()),
                metadata_block: Some(root_block.into()),
            });
        }

        Ok(Response::new(ListGraphsResponse { summaries }))
    }

    async fn push_lockbox(
        &self,
        request: Request<PushLockboxRequest>,
    ) -> Result<Response<PushLockboxResponse>, Status> {
        let req = request.into_inner();

        let graph_id = req
            .graph_id
            .parse::<GraphId>()
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

        let mut store = self.store.as_ref().clone();

        store
            .put_lockbox(graph_id, &recipient_key, &lockbox)
            .map_err(RelayError::from)
            .map_err(Status::from)?;

        Ok(Response::new(PushLockboxResponse { success: true }))
    }
}
