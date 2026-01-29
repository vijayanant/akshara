use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, DocKey, Lockbox};
use sovereign_core::graph::{Block, DocId, Manifest};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::InMemoryStore;
use sovereign_relay::service::RelayService;
use sovereign_relay::sovereign_relay::v1::discovery_service_client::DiscoveryServiceClient;
use sovereign_relay::sovereign_relay::v1::discovery_service_server::DiscoveryServiceServer;
use sovereign_relay::sovereign_relay::v1::sync_service_server::SyncServiceServer;
use sovereign_relay::sovereign_relay::v1::{ListGraphsRequest, PushLockboxRequest};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;

async fn start_server() -> (Arc<InMemoryStore>, String) {
    let store = Arc::new(InMemoryStore::new());
    let service = RelayService::new(store.clone());

    // Bind to port 0 to get a random available port
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn server in background
    let store_clone = store.clone();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SyncServiceServer::new(service.clone()))
            .add_service(DiscoveryServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (store_clone, format!("http://{}", addr))
}

#[tokio::test]
async fn integration_push_lockbox_and_list_graphs() {
    let (store, addr) = start_server().await;

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect Client
    let mut client = DiscoveryServiceClient::connect(addr.clone()).await.unwrap();

    // 1. Setup Identities
    let mut rng = OsRng;
    let alice = SecretIdentity::generate(&mut rng);
    let bob = SecretIdentity::generate(&mut rng);
    let doc_id = DocId::new();

    // 2. Setup Data (Alice Creates)
    let plaintext = b"Hello Bob";
    let doc_key = DocKey::generate(&mut rng);
    let content = BlockContent::encrypt(plaintext, &doc_key, [0u8; 12]).unwrap();

    let block = Block::new(
        content,
        "a".to_string(),
        "metadata".to_string(),
        vec![],
        &alice,
    );
    let manifest = Manifest::new(doc_id, vec![block.id()], vec![], &alice);

    // Alice manually populates the Store with the Graph Data
    use sovereign_core::store::GraphStore;
    let mut store_handle = store.as_ref().clone();
    store_handle.put_block(&block).unwrap();
    store_handle.put_manifest(&manifest).unwrap();

    // 3. Alice Invites Bob (Push Lockbox)
    // IMPORTANT: Alice uses the SAME doc_key she used to encrypt the block!
    let lockbox = Lockbox::create(bob.public().encryption_key(), &doc_key, &mut rng).unwrap();

    let request = PushLockboxRequest {
        graph_id: doc_id.0.to_string(),
        recipient_key: Some(bob.public().encryption_key().clone().into()),
        lockbox: Some(lockbox.clone().into()),
    };

    let response = client.push_lockbox(request).await.expect("Push failed");
    assert!(response.into_inner().success);

    // 4. Bob Checks Dashboard (List Graphs)
    let list_req = ListGraphsRequest {
        recipient_key: Some(bob.public().encryption_key().clone().into()),
    };

    let list_resp = client.list_graphs(list_req).await.expect("List failed");
    let summaries = list_resp.into_inner().summaries;

    // 5. Assertions
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];

    // A. Verify Metadata Block Integrity
    let returned_block_proto = summary.metadata_block.as_ref().unwrap();
    use sovereign_relay::mapping::StatusWrapper;
    let returned_block: Block = returned_block_proto
        .clone()
        .try_into()
        .map_err(|e: StatusWrapper| e.0)
        .unwrap();
    assert_eq!(returned_block.id(), block.id());

    // B. Verify Lockbox Access (Bob Decrypts)
    let returned_lockbox_proto = summary.lockbox.as_ref().unwrap();
    let returned_lockbox: Lockbox = returned_lockbox_proto
        .clone()
        .try_into()
        .map_err(|e: StatusWrapper| e.0)
        .unwrap();

    // Bob opens the lockbox using HIS private key
    let retrieved_doc_key = returned_lockbox
        .open(bob.encryption_key())
        .expect("Bob should open lockbox");

    // C. Verify Content Decryption (Bob reads Title)
    let retrieved_plaintext = returned_block
        .content()
        .decrypt(&retrieved_doc_key)
        .expect("Bob should decrypt block");

    assert_eq!(retrieved_plaintext, plaintext);
}
