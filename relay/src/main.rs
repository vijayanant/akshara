use sovereign_core::store::InMemoryStore;
use sovereign_relay::v1::discovery_service_server::DiscoveryServiceServer;
use sovereign_relay::v1::sync_service_server::SyncServiceServer;
use std::sync::Arc;
use tonic::transport::Server;

pub mod mapping;
pub mod service;
use service::RelayService;

pub mod sovereign_relay {
    pub mod v1 {
        tonic::include_proto!("sovereign.relay.v1");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = "[::1]:50051".parse()?;
    let store = Arc::new(InMemoryStore::new());
    let service = RelayService::new(store);

    println!("Sovereign Relay listening on {}", addr);

    Server::builder()
        .add_service(SyncServiceServer::new(service.clone()))
        .add_service(DiscoveryServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
