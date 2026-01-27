use async_trait::async_trait;
use sovereign_core::error::SovereignError;
use sovereign_core::graph::ManifestId;
use sovereign_core::sync::{SyncRequest, SyncResponse};

/// A trait for network operations during synchronization.
#[async_trait]
pub trait NetworkClient: Send + Sync {
    async fn send_sync_request(&self, request: SyncRequest)
    -> Result<SyncResponse, SovereignError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Negotiating,
    Fetching,
    Merging,
}

pub struct SyncClient {
    state: SyncState,
}

impl Default for SyncClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncClient {
    pub fn new() -> Self {
        Self {
            state: SyncState::Idle,
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
    ) -> Result<(), SovereignError> {
        self.state = SyncState::Negotiating;

        let request = SyncRequest::new(local_heads);
        let response = network.send_sync_request(request).await?;

        if response.missing_manifests().is_empty() {
            self.state = SyncState::Idle;
        } else {
            self.state = SyncState::Fetching;
            // TODO: Implement Fetching logic
        }

        Ok(())
    }
}
