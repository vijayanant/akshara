//! Integration tests for Graph read operations.

use akshara::{Client, ClientConfig, Graph};
use akshara_aadhaara::GraphId;

// ============================================================================
// Helper Functions
// ============================================================================

async fn create_test_client() -> Client {
    let config = ClientConfig::new().with_ephemeral_vault();
    Client::init(config).await.unwrap()
}

async fn create_test_graph_with_data(client: &Client) -> (Graph, GraphId) {
    let graph = client.create_graph().await.unwrap();
    let graph_id = graph.id();

    // Insert some test data
    graph.insert("/doc1", b"content 1".to_vec()).await.unwrap();
    graph.insert("/doc2", b"content 2".to_vec()).await.unwrap();
    graph
        .insert("/folder/doc3", b"content 3".to_vec())
        .await
        .unwrap();
    graph
        .insert("/folder/doc4", b"content 4".to_vec())
        .await
        .unwrap();

    // Seal the data
    graph.seal().await.unwrap();

    (graph, graph_id)
}

// ============================================================================
// Graph::get() Tests
// ============================================================================

#[tokio::test]
async fn graph_get_nonexistent_path() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    let result = graph.get("/nonexistent").await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn graph_get_after_insert_before_seal() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/test", b"hello".to_vec()).await.unwrap();

    // Before sealing, get should return not found (data is staged)
    let result = graph.get("/test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn graph_get_after_seal() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph
        .insert("/test", b"hello world".to_vec())
        .await
        .unwrap();
    graph.seal().await.unwrap();

    // After sealing, get should return the data
    let data = graph.get("/test").await.unwrap();
    assert_eq!(data, b"hello world");
}

#[tokio::test]
async fn graph_get_nested_path() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph
        .insert("/folder/subfolder/file", b"nested content".to_vec())
        .await
        .unwrap();
    graph.seal().await.unwrap();

    let data = graph.get("/folder/subfolder/file").await.unwrap();
    assert_eq!(data, b"nested content");
}

#[tokio::test]
async fn graph_get_binary_data() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    let binary_data = vec![0u8, 1, 2, 3, 255, 254, 253];
    graph.insert("/binary", binary_data.clone()).await.unwrap();
    graph.seal().await.unwrap();

    let retrieved = graph.get("/binary").await.unwrap();
    assert_eq!(retrieved, binary_data);
}

#[tokio::test]
async fn graph_get_empty_content() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/empty", vec![]).await.unwrap();
    graph.seal().await.unwrap();

    let data = graph.get("/empty").await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn graph_get_large_content() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    // Create 500KB of data
    let large_data = vec![0x42u8; 500 * 1024];
    graph.insert("/large", large_data.clone()).await.unwrap();
    graph.seal().await.unwrap();

    let retrieved = graph.get("/large").await.unwrap();
    assert_eq!(retrieved, large_data);
}

// ============================================================================
// Graph::exists() Tests
// ============================================================================

#[tokio::test]
async fn graph_exists_nonexistent_path() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    let exists = graph.exists("/nonexistent").await.unwrap();
    assert!(!exists);
}

#[tokio::test]
async fn graph_exists_after_seal() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/test", b"content".to_vec()).await.unwrap();

    // Before sealing
    let exists = graph.exists("/test").await.unwrap();
    assert!(!exists);

    // After sealing
    graph.seal().await.unwrap();
    let exists = graph.exists("/test").await.unwrap();
    assert!(exists);
}

// ============================================================================
// Graph::list() Tests
// ============================================================================

#[tokio::test]
async fn graph_list_empty_graph() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    let paths = graph.list("").await.unwrap();
    assert!(paths.is_empty());
}

#[tokio::test]
async fn graph_list_root_prefix() {
    let (graph, _) = create_test_graph_with_data(&create_test_client().await).await;

    let paths = graph.list("").await.unwrap();
    assert!(paths.contains(&"/doc1".to_string()));
    assert!(paths.contains(&"/doc2".to_string()));
    assert!(paths.contains(&"/folder/doc3".to_string()));
    assert!(paths.contains(&"/folder/doc4".to_string()));
}

#[tokio::test]
async fn graph_list_with_prefix() {
    let (graph, _) = create_test_graph_with_data(&create_test_client().await).await;

    let paths = graph.list("/folder").await.unwrap();
    assert!(paths.contains(&"/folder/doc3".to_string()));
    assert!(paths.contains(&"/folder/doc4".to_string()));
    assert!(!paths.contains(&"/doc1".to_string()));
}

#[tokio::test]
async fn graph_list_with_prefix_no_matches() {
    let (graph, _) = create_test_graph_with_data(&create_test_client().await).await;

    let paths = graph.list("/nonexistent").await.unwrap();
    assert!(paths.is_empty());
}

#[tokio::test]
async fn graph_list_nested_prefix() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/a/b/c/d", b"deep".to_vec()).await.unwrap();
    graph.seal().await.unwrap();

    let paths = graph.list("/a/b").await.unwrap();
    assert!(paths.contains(&"/a/b/c/d".to_string()));
}

#[tokio::test]
async fn graph_list_after_multiple_seals() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    // First seal
    graph.insert("/doc1", b"first".to_vec()).await.unwrap();
    graph.seal().await.unwrap();

    // Second seal - CRDT-style: merges with existing state
    graph.insert("/doc2", b"second".to_vec()).await.unwrap();
    graph.seal().await.unwrap();

    let paths = graph.list("").await.unwrap();
    // Both documents should be present (CRDT merge)
    assert!(paths.contains(&"/doc1".to_string()));
    assert!(paths.contains(&"/doc2".to_string()));
}

#[tokio::test]
async fn graph_list_after_update() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/test", b"original".to_vec()).await.unwrap();
    graph.seal().await.unwrap();

    // Update the same path
    graph.update("/test", b"updated".to_vec()).await.unwrap();
    graph.seal().await.unwrap();

    let paths = graph.list("").await.unwrap();
    assert!(paths.contains(&"/test".to_string()));

    // Should have updated content
    let data = graph.get("/test").await.unwrap();
    assert_eq!(data, b"updated");
}

#[tokio::test]
async fn graph_list_after_delete() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph
        .insert("/to-delete", b"content".to_vec())
        .await
        .unwrap();
    graph.seal().await.unwrap();

    // Delete
    graph.delete("/to-delete").await.unwrap();
    graph.seal().await.unwrap();

    let paths = graph.list("").await.unwrap();
    // Deleted path should not appear
    assert!(!paths.contains(&"/to-delete".to_string()));
}

// ============================================================================
// Graph::get() with Special Characters
// ============================================================================

#[tokio::test]
async fn graph_get_with_unicode_path() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph
        .insert("/日本語/ファイル", b"unicode content".to_vec())
        .await
        .unwrap();
    graph.seal().await.unwrap();

    let data = graph.get("/日本語/ファイル").await.unwrap();
    assert_eq!(data, b"unicode content");
}

#[tokio::test]
async fn graph_get_with_spaces_in_path() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph
        .insert("/path with spaces/file", b"spaces content".to_vec())
        .await
        .unwrap();
    graph.seal().await.unwrap();

    let data = graph.get("/path with spaces/file").await.unwrap();
    assert_eq!(data, b"spaces content");
}

// ============================================================================
// Graph Read Performance
// ============================================================================

#[tokio::test]
async fn graph_get_multiple_reads() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    // Insert multiple documents
    for i in 0..10 {
        graph
            .insert(&format!("/doc{}", i), format!("content {}", i).into_bytes())
            .await
            .unwrap();
    }
    graph.seal().await.unwrap();

    // Read all documents
    for i in 0..10 {
        let data = graph.get(&format!("/doc{}", i)).await.unwrap();
        assert_eq!(data, format!("content {}", i).as_bytes());
    }
}
