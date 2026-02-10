use async_trait::async_trait;
use rand::rngs::OsRng;
use sovereign_core::graph::{Block, BlockId, GraphId, Manifest, ManifestId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};
use sovereign_core::sync::{SyncRequest, SyncResponse};
use sovereign_sdk::error::{NetworkError, SdkError};
use sovereign_sdk::sync::{NetworkClient, SyncClient, SyncState};

#[derive(Default)]
struct MockNetwork {
    should_have_missing: bool,
    should_fail_request: bool,
    should_fail_fetch: bool,
    tamper_block: bool,
    manifest: Option<Manifest>,
    block: Option<Block>,
}

#[async_trait]
impl NetworkClient for MockNetwork {
    async fn send_sync_request(&self, _request: SyncRequest) -> Result<SyncResponse, SdkError> {
        if self.should_fail_request {
            return Err(SdkError::Network(NetworkError::ConnectionFailed(
                "Mock Failure".to_string(),
            )));
        }

        if self.should_have_missing {
            let m_id = self.manifest.as_ref().unwrap().id();
            let b_id = self.block.as_ref().unwrap().id();
            Ok(SyncResponse::new(vec![m_id], vec![b_id]))
        } else {
            Ok(SyncResponse::new(vec![], vec![]))
        }
    }

    async fn fetch_manifest(&self, _id: &ManifestId) -> Result<Manifest, SdkError> {
        if self.should_fail_fetch {
            return Err(SdkError::Network(NetworkError::Timeout));
        }
        Ok(self.manifest.clone().unwrap())
    }

    async fn fetch_block(&self, _id: &BlockId) -> Result<Block, SdkError> {
        if self.should_fail_fetch {
            return Err(SdkError::Network(NetworkError::Timeout));
        }

        let block = self.block.clone().unwrap();
        if self.tamper_block {
            // Placeholder for tampering logic
        }
        Ok(block)
    }
}

// ... helper to create valid data ...
fn create_valid_data() -> (Manifest, Block) {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();

    let block = Block::new(
        sovereign_core::crypto::BlockContent::encrypt(
            &[],
            &sovereign_core::crypto::GraphKey::from([0u8; 32]),
            [0u8; 12],
        )
        .unwrap(),
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );

    let manifest = Manifest::new(graph_id, vec![block.id()], vec![], &identity);
    (manifest, block)
}

#[test]
fn client_starts_in_idle_state() {
    let store = InMemoryStore::new();
    let client = SyncClient::new(store);
    assert_eq!(client.state(), SyncState::Idle);
}

#[tokio::test]
async fn client_transitions_to_idle_if_already_synced() {
    let store = InMemoryStore::new();
    let network = MockNetwork::default();
    let mut client = SyncClient::new(store);

    client.perform_sync(&network, vec![]).await.unwrap();

    assert_eq!(client.state(), SyncState::Idle);
}

#[tokio::test]
async fn client_fetches_and_saves_missing_data() {
    let (manifest, block) = create_valid_data();
    let store = InMemoryStore::new();
    let network = MockNetwork {
        should_have_missing: true,
        manifest: Some(manifest.clone()),
        block: Some(block.clone()),
        ..Default::default()
    };
    let mut client = SyncClient::new(store.clone());

    client.perform_sync(&network, vec![]).await.unwrap();

    assert_eq!(client.state(), SyncState::Idle);
    assert!(store.get_manifest(&manifest.id()).unwrap().is_some());
    assert!(store.get_block(&block.id()).unwrap().is_some());
}

#[tokio::test]
async fn client_handles_network_error_gracefully() {
    let store = InMemoryStore::new();
    let network = MockNetwork {
        should_fail_request: true,
        ..Default::default()
    };
    let mut client = SyncClient::new(store);
    let result = client.perform_sync(&network, vec![]).await;

    // Assert it is a Network Error
    match result {
        Err(SdkError::Network(_)) => {}
        _ => panic!("Expected NetworkError"),
    }
}

#[tokio::test]
async fn client_handles_partial_fetch_failure() {
    let (manifest, block) = create_valid_data();
    let store = InMemoryStore::new();
    let network = MockNetwork {
        should_have_missing: true,
        should_fail_fetch: true,
        manifest: Some(manifest),
        block: Some(block),
        ..Default::default()
    };

    let mut client = SyncClient::new(store.clone());
    let result = client.perform_sync(&network, vec![]).await;

    // Assert it is a Network Error
    match result {
        Err(SdkError::Network(_)) => {}
        _ => panic!("Expected NetworkError"),
    }
}
