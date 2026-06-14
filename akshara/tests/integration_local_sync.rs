#![allow(clippy::too_many_lines)]

use akshara::{Client, ClientConfig, Graph, LocalMemoryTransport, SyncMode};
use akshara_aadhaara::GraphStore;
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
        .sync_graph(graph_id, graph_a.store(), &graph_key, SyncMode::Full)
        .await
        .unwrap();
    assert_eq!(report_a.graphs_synced, 1);

    // 6. Verify Specialist Client B can now read the patient record!
    let name_b = graph_b.get("/patient/name").await.unwrap();
    assert_eq!(name_b, b"Priya Sharma");

    let allergies_b = graph_b.get("/patient/allergies").await.unwrap();
    assert_eq!(allergies_b, b"Penicillin");
}

#[tokio::test]
async fn test_local_sync_sovereign_collaborative_workflow() {
    // 1. Initialize Patient Client A and Collaborator Client B
    let client_a = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await
    .unwrap();
    let client_b = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await
    .unwrap();

    let identity_b = client_b.vault().get_identity(None).await.unwrap();

    // 2. Client A creates a graph and inserts demographics
    let graph_a = client_a.create_graph().await.unwrap();
    let graph_id = graph_a.id();
    let graph_key = graph_a.key().clone();

    graph_a
        .insert("/patient/demographics", b"Priya Sharma".to_vec())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    // 3. Client A authorizes Client B's root signing key
    graph_a
        .authorize_collaborator(identity_b.public().signing_key())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    // 4. Set up Client B's graph handle (simulating lockbox retrieval)
    let dummy_b = client_b.create_graph().await.unwrap();
    let store_b = dummy_b.store().clone();
    let graph_b = Graph::new(
        graph_id,
        graph_key.clone(),
        client_b.vault().clone(),
        store_b.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // 5. Sync from A to B (B pulls A's graph state and A's Identity Graph)
    let transport_a_to_b = Arc::new(LocalMemoryTransport::new(store_b.clone()));
    let sync_engine_a = akshara::sync::SyncEngine::new(transport_a_to_b, client_a.vault().clone());
    sync_engine_a
        .sync_graph(graph_id, graph_a.store(), &graph_key, SyncMode::Full)
        .await
        .unwrap();

    // 6. Client B adds a consultation note and flushes
    graph_b
        .insert("/consultations/0", b"Note by Dr. Mehta".to_vec())
        .await
        .unwrap();
    graph_b.flush().await.unwrap();

    // 7. Sync back from B to A (A pulls B's updates + B's Identity Graph)
    let transport_b_to_a = Arc::new(LocalMemoryTransport::new(graph_a.store().clone()));
    let sync_engine_b = akshara::sync::SyncEngine::new(transport_b_to_a, client_b.vault().clone());
    sync_engine_b
        .sync_graph(graph_id, graph_b.store(), &graph_key, SyncMode::Full)
        .await
        .unwrap();

    // 8. Verify Client A can read B's consultation note
    let note = graph_a.get("/consultations/0").await.unwrap();
    assert_eq!(note, b"Note by Dr. Mehta");
}

#[tokio::test]
async fn test_sync_engine_detects_concurrent_path_conflict() {
    // 1. Client A and Client B start from the same state
    let client_a = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await
    .unwrap();
    let client_b = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await
    .unwrap();

    let graph_a = client_a.create_graph().await.unwrap();
    let graph_id = graph_a.id();
    let graph_key = graph_a.key().clone();

    // Genesis setup: insert a baseline file
    graph_a
        .insert("/notes", b"Base notes".to_vec())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    // Authorize Client B on Graph A
    let identity_b = client_b.vault().get_identity(None).await.unwrap();
    graph_a
        .authorize_collaborator(identity_b.public().signing_key())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    // Replicate baseline state to Client B
    let dummy_b = client_b.create_graph().await.unwrap();
    let store_b = dummy_b.store().clone();
    let transport_a_to_b = Arc::new(LocalMemoryTransport::new(store_b.clone()));
    let sync_a = akshara::sync::SyncEngine::new(transport_a_to_b, client_a.vault().clone());
    sync_a
        .sync_graph(graph_id, graph_a.store(), &graph_key, SyncMode::Full)
        .await
        .unwrap();

    // Now instantiate Graph B handle
    let graph_b = Graph::new(
        graph_id,
        graph_key.clone(),
        client_b.vault().clone(),
        store_b.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // 2. CONCURRENT EDITS: A edits /notes, B edits /notes concurrently
    graph_a
        .insert("/notes", b"Edited by Client A".to_vec())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    graph_b
        .insert("/notes", b"Edited by Client B".to_vec())
        .await
        .unwrap();
    graph_b.flush().await.unwrap();

    // 3. Sync A's state to B: B should receive A's branch, resulting in two concurrent heads
    let transport_a_to_b2 = Arc::new(LocalMemoryTransport::new(store_b.clone()));
    let sync_a2 = akshara::sync::SyncEngine::new(transport_a_to_b2, client_a.vault().clone());

    // Perform sync: B pulls from A
    let report = sync_a2
        .sync_graph(graph_id, graph_a.store(), &graph_key, SyncMode::Full)
        .await
        .unwrap();

    // B's store should now have 2 heads for this graph
    let heads = store_b.get_heads(&graph_id).await.unwrap();
    println!("DEBUG: heads of B: {:?}", heads);
    assert_eq!(
        heads.len(),
        2,
        "Graph must have 2 concurrent heads after syncing a fork"
    );

    // The SyncReport should have detected 1 conflict
    assert_eq!(report.conflicts_detected, 1);
    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];
    assert_eq!(conflict.path, "/notes");
    assert_eq!(conflict.heads.len(), 2);
    assert_eq!(conflict.divergent_blocks.len(), 2);
}

#[tokio::test]
async fn test_local_sync_pull_from_remote_peer() {
    // 1. Initialize Client A (Remote Peer)
    let config_a = ClientConfig::new()
        .with_ephemeral_vault()
        .with_in_memory_storage();
    let client_a = Client::init(config_a).await.unwrap();

    // 2. Initialize Client B (Local Client)
    let config_b = ClientConfig::new()
        .with_ephemeral_vault()
        .with_in_memory_storage();
    let client_b = Client::init(config_b).await.unwrap();

    // 3. Client A creates a graph and inserts demographics
    let graph_a = client_a.create_graph().await.unwrap();
    let graph_id = graph_a.id();
    let graph_key = graph_a.key().clone();

    graph_a
        .insert("/profile/nickname", b"Doctor Jones".to_vec())
        .await
        .unwrap();
    graph_a.flush().await.unwrap();

    // 4. Construct Client B's Graph handle and store
    let dummy_b = client_b.create_graph().await.unwrap();
    let store_b = dummy_b.store().clone();

    let graph_b = Graph::new(
        graph_id,
        graph_key.clone(),
        client_b.vault().clone(),
        store_b.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // Verify B's store does not have the profile yet
    let err = graph_b.get("/profile/nickname").await;
    assert!(err.is_err());

    // 5. B pulls from A: B's sync engine is initialized with a transport pointing to A's store
    let transport_to_a = Arc::new(LocalMemoryTransport::new(graph_a.store().clone()));
    let sync_engine_b = akshara::sync::SyncEngine::new(transport_to_a, client_b.vault().clone());

    // B syncs graph -> B pulls missing portions from A
    let report_b = sync_engine_b
        .sync_graph(graph_id, &store_b, &graph_key, SyncMode::Full)
        .await
        .unwrap();

    assert_eq!(report_b.graphs_synced, 1);
    assert!(report_b.manifests_received > 0);

    // 6. Verify B can now read A's profile data
    let name_b = graph_b.get("/profile/nickname").await.unwrap();
    assert_eq!(name_b, b"Doctor Jones");
}
