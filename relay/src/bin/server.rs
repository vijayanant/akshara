use sovereign_core::store::InMemoryStore;
use sovereign_relay::discovery::RelayDiscoveryService;
use sovereign_relay::sovereign_relay::v1::discovery_service_server::DiscoveryServiceServer;
use sovereign_relay::sovereign_relay::v1::sync_service_server::SyncServiceServer;
use sovereign_relay::sync::RelaySyncService;
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = "[::1]:50051".parse()?;
    let store = Arc::new(InMemoryStore::new());

    let sync_service = RelaySyncService {
        store: store.clone(),
    };
    let discovery_service = RelayDiscoveryService {
        store: store.clone(),
    };

    println!("Sovereign Relay listening on {}", addr);

    Server::builder()
        .add_service(SyncServiceServer::new(sync_service))
        .add_service(DiscoveryServiceServer::new(discovery_service))
        .serve(addr)
        .await?;

    Ok(())
}
