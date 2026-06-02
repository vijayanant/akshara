use akshara::{Client, ClientConfig, Graph, LocalMemoryTransport};
use std::sync::Arc;

#[tokio::test]
async fn test_local_in_memory_sync_between_two_clients() {
    // 1. Initialize Doctor Client A
    let config_a = ClientConfig::new()
        .with_ephemeral_vault()
        .with_in_memory_storage();
    let client_a = Client::init(config_a).await.unwrap();

    // 2. Initialize Specialist Client B
    let config_b = ClientConfig::new()
        .with_ephemeral_vault()
        .with_in_memory_storage();
    let client_b = Client::init(config_b).await.unwrap();

    // 3. Client A creates a graph and inserts patient records
    let graph_a = client_a.create_graph().await.unwrap();
    let graph_id = graph_a.id();
    let graph_key = graph_a.key().clone();

    graph_a
        .insert("/patient/name", b"Priya Sharma".to_vec())
        .await
        .unwrap();
    graph_a
        .insert("/patient/allergies", b"Penicillin".to_vec())
        .await
        .unwrap();
    let report = graph_a.flush().await.unwrap();
    assert_eq!(report.blocks_created, 2);

    // Verify A can read locally
    let name_a = graph_a.get("/patient/name").await.unwrap();
    assert_eq!(name_a, b"Priya Sharma");

    // 4. Construct Client B's Graph handle for the same graph
    // (In a real system, B would receive the GraphId and GraphKey via a Lockbox share/QR code scan)
    // To get B's store, we create a dummy graph on client_b to get a reference to its store:
    let dummy_graph = client_b.create_graph().await.unwrap();
    let store_b = dummy_graph.store().clone();

    let graph_b = Graph::new(
        graph_id,
        graph_key.clone(),
        client_b.vault().clone(),
        store_b.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // Verify B cannot read the data yet (its store is empty for this graph)
    let err = graph_b.get("/patient/name").await;
    assert!(err.is_err());

    // 5. Sync from A to B: A pushes to B's store
    let transport_to_b = Arc::new(LocalMemoryTransport::new(store_b.clone()));
    let sync_engine_a = akshara::sync::SyncEngine::new(transport_to_b, client_a.vault().clone());

    let report_a = sync_engine_a
        .sync_graph(graph_id, graph_a.store(), &graph_key)
        .await
        .unwrap();
    assert_eq!(report_a.graphs_synced, 1);

    // 6. Verify Specialist Client B can now read the patient record!
    let name_b = graph_b.get("/patient/name").await.unwrap();
    assert_eq!(name_b, b"Priya Sharma");

    let allergies_b = graph_b.get("/patient/allergies").await.unwrap();
    assert_eq!(allergies_b, b"Penicillin");
}
