use akshara_aadhaara::{GraphId, GraphKey, InMemoryStore, SecretIdentity};
use akshara_schema::adapters::{
    BlockAdapter, ChunkedBlockAdapter, CollectionBlockAdapter, StandaloneBlockAdapter,
    TextDocumentAdapter,
};

#[tokio::test]
async fn test_standalone_adapter_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let value = "Hello, Standalone World!".to_string();

    // Serialize
    let address =
        StandaloneBlockAdapter::serialize(&value, &graph_id, &key, &identity, &store, "meta/title")
            .await
            .unwrap();

    // Deserialize
    let recovered: String = StandaloneBlockAdapter::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    assert_eq!(value, recovered);
}

#[tokio::test]
async fn test_text_document_adapter_collaborative_sentence_splitting() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let text = "Clause 1. Clause 2? Clause 3!".to_string();

    // Serialize
    let address = TextDocumentAdapter::serialize(
        &text,
        &graph_id,
        &key,
        &identity,
        &store,
        "content/clauses",
    )
    .await
    .unwrap();

    // Deserialize
    let recovered: String = TextDocumentAdapter::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    assert_eq!(text, recovered);
}

#[tokio::test]
async fn test_chunked_block_adapter_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Set custom chunk size for quick testing (10 KB)
    ChunkedBlockAdapter::set_chunk_size(10 * 1024);

    // Create a 25 KB payload of random bytes (splits into 3 chunks)
    use rand::RngCore;
    let mut data = vec![0u8; 25 * 1024];
    rng.fill_bytes(&mut data);

    // Serialize
    let address =
        ChunkedBlockAdapter::serialize(&data, &graph_id, &key, &identity, &store, "payload/data")
            .await
            .unwrap();

    // Deserialize
    let recovered: Vec<u8> = ChunkedBlockAdapter::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    // Reset to default chunk size (1 MB) to prevent side effects in other tests
    ChunkedBlockAdapter::set_chunk_size(1024 * 1024);

    assert_eq!(data, recovered);
}

#[tokio::test]
async fn test_collection_block_adapter_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let items = vec![
        "Item Alpha".to_string(),
        "Item Beta".to_string(),
        "Item Gamma".to_string(),
    ];

    // Serialize
    let address =
        CollectionBlockAdapter::serialize(&items, &graph_id, &key, &identity, &store, "items")
            .await
            .unwrap();

    // Deserialize
    let recovered: Vec<String> =
        CollectionBlockAdapter::deserialize(&address, &graph_id, &key, &store)
            .await
            .unwrap();

    assert_eq!(items, recovered);
}
