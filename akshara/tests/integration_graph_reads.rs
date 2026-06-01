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
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

    let data = graph.get("/folder/subfolder/file").await.unwrap();
    assert_eq!(data, b"nested content");
}

#[tokio::test]
async fn graph_get_binary_data() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    let binary_data = vec![0u8, 1, 2, 3, 255, 254, 253];
    graph.insert("/binary", binary_data.clone()).await.unwrap();
    graph.flush().await.unwrap();

    let retrieved = graph.get("/binary").await.unwrap();
    assert_eq!(retrieved, binary_data);
}

#[tokio::test]
async fn graph_get_empty_content() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    graph.insert("/empty", vec![]).await.unwrap();
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();
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
    graph.flush().await.unwrap();

    let paths = graph.list("/a/b").await.unwrap();
    assert!(paths.contains(&"/a/b/c/d".to_string()));
}

#[tokio::test]
async fn graph_list_after_multiple_seals() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();

    // First seal
    graph.insert("/doc1", b"first".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

    // Second seal - CRDT-style: merges with existing state
    graph.insert("/doc2", b"second".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

    // Update the same path
    graph.update("/test", b"updated".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

    // Delete
    graph.delete("/to-delete").await.unwrap();
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

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
    graph.flush().await.unwrap();

    // Read all documents
    for i in 0..10 {
        let data = graph.get(&format!("/doc{}", i)).await.unwrap();
        assert_eq!(data, format!("content {}", i).as_bytes());
    }
}

// ============================================================================
// Graph History Tests
// ============================================================================

#[tokio::test]
async fn graph_history_queries() {
    let client = create_test_client().await;
    let graph = client.create_graph().await.unwrap();
    let path = "/test/doc-history";

    // 1. First write (v1)
    graph.insert(path, b"v1".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

    // 2. Second write (v2)
    graph.update(path, b"v2".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

    // 3. Third write (v3)
    graph.update(path, b"v3".to_vec()).await.unwrap();
    graph.flush().await.unwrap();

    // 4. Retrieve raw history
    let raw_history = graph.get_history(path).await.unwrap();
    assert_eq!(raw_history.len(), 3);
    assert_eq!(raw_history[0].value, b"v1");
    assert_eq!(raw_history[1].value, b"v2");
    assert_eq!(raw_history[2].value, b"v3");

    // Check that CIDs differ
    assert_ne!(raw_history[0].block_id, raw_history[1].block_id);
    assert_ne!(raw_history[1].block_id, raw_history[2].block_id);

    // 5. Retrieve typed history (using a basic String schema or wrapper)
    // Since String implements AksharaDocument via adapters or raw bytes:
    // Wait, let's see: String is not directly implementing AksharaDocument by default,
    // but we can define a simple struct in this test scope or use custom wrapper.
    // Let's define a simple Note struct with AksharaDocument derive.
    #[derive(
        akshara::schema::AksharaDocument,
        serde::Serialize,
        serde::Deserialize,
        Clone,
        PartialEq,
        Eq,
        Debug,
    )]
    struct TestNote {
        pub text: String,
    }

    let note_path = "/test/note-history";
    let n1 = TestNote {
        text: "v1".to_string(),
    };
    graph.insert_document(note_path, &n1).await.unwrap();
    graph.flush().await.unwrap();

    let n2 = TestNote {
        text: "v2".to_string(),
    };
    graph.insert_document(note_path, &n2).await.unwrap();
    graph.flush().await.unwrap();

    let typed_history = graph.history::<TestNote>(note_path).await.unwrap();
    assert_eq!(typed_history.len(), 2);
    assert_eq!(typed_history[0].value.text, "v1");
    assert_eq!(typed_history[1].value.text, "v2");
    assert_eq!(typed_history[0].author_fingerprint.len(), 16); // 8 bytes in hex = 16 chars

    // Verify load works as well
    let loaded = graph.get_document::<TestNote>(note_path).await.unwrap();
    assert_eq!(loaded.text, "v2");
}
