use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, GraphKey, Lockbox};
use sovereign_core::graph::{Block, GraphId, Manifest};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::InMemoryStore;
use sovereign_relay::discovery::RelayDiscoveryService;
use sovereign_relay::sovereign_relay::v1::discovery_service_client::DiscoveryServiceClient;
use sovereign_relay::sovereign_relay::v1::discovery_service_server::DiscoveryServiceServer;
use sovereign_relay::sovereign_relay::v1::sync_service_client::SyncServiceClient;
use sovereign_relay::sovereign_relay::v1::sync_service_server::SyncServiceServer;
use sovereign_relay::sovereign_relay::v1::{
    ListGraphsRequest, PushLockboxRequest, PushRequest, SyncRequest,
};
use sovereign_relay::sync::RelaySyncService;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;

async fn start_server() -> (Arc<InMemoryStore>, String) {
    let store = Arc::new(InMemoryStore::new());

    let sync_service = RelaySyncService {
        store: store.clone(),
    };
    let discovery_service = RelayDiscoveryService {
        store: store.clone(),
    };

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let store_clone = store.clone();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SyncServiceServer::new(sync_service))
            .add_service(DiscoveryServiceServer::new(discovery_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (store_clone, format!("http://{}", addr))
}

#[tokio::test]
async fn integration_full_collaboration_lifecycle() {
    let (_store, addr) = start_server().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect Clients
    let mut discovery_client = DiscoveryServiceClient::connect(addr.clone()).await.unwrap();
    let mut sync_client = SyncServiceClient::connect(addr.clone()).await.unwrap();

    // 1. Identities
    let mut rng = OsRng;
    let alice = SecretIdentity::generate(&mut rng);
    let bob = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let graph_key = GraphKey::generate(&mut rng);

    // 2. Alice Creates Content
    let plaintext = b"Grand System Data";
    let content = BlockContent::encrypt(plaintext, &graph_key, [0u8; 12]).unwrap();
    let block = Block::new(
        content,
        "a".to_string(),
        "metadata".to_string(),
        vec![],
        &alice,
    );
    let manifest = Manifest::new(graph_id, vec![block.id()], vec![], &alice);

    // 3. Alice Pushes Data (gRPC)
    let push_req = PushRequest {
        manifests: vec![manifest.clone().into()],
        blocks: vec![block.clone().into()],
    };
    sync_client.push(push_req).await.expect("Alice Push failed");

    // 4. Alice Shares with Bob (gRPC)
    let lockbox = Lockbox::create(bob.public().encryption_key(), &graph_key, &mut rng).unwrap();
    let share_req = PushLockboxRequest {
        graph_id: graph_id.0.to_string(),
        recipient_key: Some(bob.public().encryption_key().clone().into()),
        lockbox: Some(lockbox.into()),
    };
    discovery_client
        .push_lockbox(share_req)
        .await
        .expect("Alice Share failed");

    // 5. Bob Discovers (gRPC)
    let list_req = ListGraphsRequest {
        recipient_key: Some(bob.public().encryption_key().clone().into()),
    };
    let list_resp = discovery_client
        .list_graphs(list_req)
        .await
        .expect("Bob List failed");
    let summaries = list_resp.into_inner().summaries;
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];

    // 6. Bob Syncs Content (gRPC)
    let sync_req = SyncRequest {
        graph_id: graph_id.0.to_string(),
        heads: vec![], // Bob knows nothing
    };
    let mut stream = sync_client
        .sync(sync_req)
        .await
        .expect("Bob Sync failed")
        .into_inner();

    let mut received_manifest = None;
    let mut received_block = None;

    use sovereign_relay::sovereign_relay::v1::sync_response_item::Item;
    while let Some(item_result) = stream.message().await.unwrap() {
        match item_result.item {
            Some(Item::Manifest(m)) => received_manifest = Some(m),
            Some(Item::Block(b)) => received_block = Some(b),
            None => {}
        }
    }

    // 7. Final Verification
    let m_proto = received_manifest.expect("Missing manifest in sync");
    let b_proto = received_block.expect("Missing block in sync");

    use sovereign_relay::mapping::StatusWrapper;
    let m: Manifest = m_proto.try_into().map_err(|e: StatusWrapper| e.0).unwrap();
    let b: Block = b_proto.try_into().map_err(|e: StatusWrapper| e.0).unwrap();

    assert_eq!(m.id(), manifest.id());
    assert_eq!(b.id(), block.id());

    // Bob decrypts everything
    let bob_lockbox: Lockbox = summary
        .lockbox
        .as_ref()
        .unwrap()
        .clone()
        .try_into()
        .map_err(|e: StatusWrapper| e.0)
        .unwrap();
    let retrieved_key = bob_lockbox
        .open(bob.encryption_key())
        .expect("Bob fails lockbox");
    let retrieved_plaintext = b
        .content()
        .decrypt(&retrieved_key)
        .expect("Bob fails decrypt");

    assert_eq!(retrieved_plaintext, plaintext);
}
