use akshara::{Client, ClientConfig, Graph};
use akshara_aadhaara::GraphStore;
use akshara_schema::AksharaDocument;
use rand::RngCore;

#[derive(AksharaDocument, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
struct LegalCase {
    pub title: String,

    #[collaborative_text]
    pub details: String,

    #[chunked]
    pub evidence: Vec<u8>,

    #[collection]
    pub notes: Vec<String>,
}

async fn create_test_graph() -> Graph {
    let config = ClientConfig::new()
        .with_ephemeral_vault()
        .with_in_memory_storage();
    let client = Client::init(config).await.unwrap();
    client.create_graph().await.unwrap()
}

#[tokio::test]
async fn test_document_pipeline_e2e_roundtrip() {
    let graph = create_test_graph().await;
    let doc_path = "/cases/alpha";

    // 1. Generate test data
    let mut rng = rand::rngs::OsRng;
    let mut evidence = vec![0u8; 15 * 1024]; // 15 KB (will split into chunks if we adjust chunk size)
    rng.fill_bytes(&mut evidence);

    // Set a custom small chunk size for testing chunk boundary logic
    akshara_schema::adapters::ChunkedBlockAdapter::set_chunk_size(4 * 1024); // 4 KB chunks

    let original = LegalCase {
        title: "State vs. Doe".to_string(),
        details: "Defendant was seen at the bank. He wore a dark hat? The witness confirms!"
            .to_string(),
        evidence,
        notes: vec![
            "First note: investigated location.".to_string(),
            "Second note: analyzed hats.".to_string(),
        ],
    };

    // 2. Insert document
    graph.insert_document(doc_path, &original).await.unwrap();

    // Verify it is staged but not committed yet (genesis manifest head exists)
    let heads = graph.store().get_heads(&graph.id()).await.unwrap();
    assert_eq!(heads.len(), 1);

    // 3. Flush to Merkle-DAG
    let report = graph.flush().await.unwrap();
    assert!(report.blocks_created > 0);

    // Verify heads updated to the new manifest
    let new_heads = graph.store().get_heads(&graph.id()).await.unwrap();
    assert_eq!(new_heads.len(), 1);
    assert_ne!(heads[0], new_heads[0]);

    // 4. Retrieve document and verify correctness
    let recovered: LegalCase = graph.get_document(doc_path).await.unwrap();
    assert_eq!(original, recovered);

    // 5. Verify the schema metadata block exists in the store
    let schema_path = format!("{}/.akshara.schema", doc_path);
    assert!(graph.exists(&schema_path).await.unwrap());

    // Clean up static config
    akshara_schema::adapters::ChunkedBlockAdapter::set_chunk_size(1024 * 1024);
}
