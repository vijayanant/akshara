use async_trait::async_trait;
use sovereign_core::error::SovereignError;
use sovereign_core::graph::ManifestId;
use sovereign_core::sync::{SyncRequest, SyncResponse};
use sovereign_sdk::sync::{NetworkClient, SyncClient, SyncState};

#[test]
fn client_starts_in_idle_state() {
    let client = SyncClient::new();
    assert_eq!(client.state(), SyncState::Idle);
}

struct MockNetwork {
    should_have_missing: bool,
}

#[async_trait]
impl NetworkClient for MockNetwork {
    async fn send_sync_request(
        &self,
        _request: SyncRequest,
    ) -> Result<SyncResponse, SovereignError> {
        if self.should_have_missing {
            // Return one missing manifest ID
            Ok(SyncResponse::new(vec![ManifestId([1u8; 32])], vec![]))
        } else {
            Ok(SyncResponse::new(vec![], vec![]))
        }
    }
}

#[tokio::test]
async fn client_transitions_to_idle_if_already_synced() {
    let network = MockNetwork {
        should_have_missing: false,
    };
    let mut client = SyncClient::new();

    client.perform_sync(&network, vec![]).await.unwrap();

    assert_eq!(client.state(), SyncState::Idle);
}

#[tokio::test]
async fn client_transitions_to_fetching_if_missing_data() {
    let network = MockNetwork {
        should_have_missing: true,
    };
    let mut client = SyncClient::new();

    client.perform_sync(&network, vec![]).await.unwrap();

    assert_eq!(client.state(), SyncState::Fetching);
}
