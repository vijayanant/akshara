use crate::error::SdkError;
use async_trait::async_trait;
use sovereign_core::graph::{Block, BlockId, Manifest, ManifestId};
use sovereign_core::store::GraphStore;
use sovereign_core::sync::{SyncRequest, SyncResponse};

/// A trait for network operations during synchronization.
#[async_trait]
pub trait NetworkClient: Send + Sync {
    async fn send_sync_request(&self, request: SyncRequest) -> Result<SyncResponse, SdkError>;

    async fn fetch_manifest(&self, id: &ManifestId) -> Result<Manifest, SdkError>;

    async fn fetch_block(&self, id: &BlockId) -> Result<Block, SdkError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Negotiating,
    Fetching,
    Merging,
}

pub struct SyncClient<S: GraphStore> {
    state: SyncState,
    store: S,
}

impl<S: GraphStore> SyncClient<S> {
    pub fn new(store: S) -> Self {
        Self {
            state: SyncState::Idle,
            store,
        }
    }

    pub fn state(&self) -> SyncState {
        self.state.clone()
    }

    /// Starts the synchronization process.
    ///
    /// This method initiates the negotiation phase with the Relay.
    pub async fn perform_sync(
        &mut self,
        network: &impl NetworkClient,
        local_heads: Vec<ManifestId>,
    ) -> Result<(), SdkError> {
        self.state = SyncState::Negotiating;

        let request = SyncRequest::new(local_heads);
        let response = network.send_sync_request(request).await?;

        if response.missing_manifests().is_empty() {
            self.state = SyncState::Idle;
        } else {
            self.state = SyncState::Fetching;

            // 1. Fetch Manifests
            for m_id in response.missing_manifests() {
                let manifest = network.fetch_manifest(m_id).await?;
                // Security: Verify integrity before saving
                // We map SovereignError -> SdkError::Protocol
                manifest.verify_integrity().map_err(SdkError::Protocol)?;
                self.store
                    .put_manifest(&manifest)
                    .map_err(SdkError::Protocol)?;
            }

            // 2. Fetch Blocks
            for b_id in response.missing_blocks() {
                let block = network.fetch_block(b_id).await?;
                // Security: Verify integrity before saving
                block.verify_integrity().map_err(SdkError::Protocol)?;
                self.store.put_block(&block).map_err(SdkError::Protocol)?;
            }

            // TODO: Transition to Merging if needed
            self.state = SyncState::Idle;
        }

        Ok(())
    }
}
