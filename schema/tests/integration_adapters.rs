use akshara_aadhaara::{GraphId, GraphKey, InMemoryStore, SecretIdentity};
use akshara_schema::adapters::{BlockAdapter, StandaloneBlockAdapter, TextDocumentAdapter};

#[tokio::test]
async fn test_standalone_adapter_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let value = "Hello, Standalone World!".to_string();
    
    // Serialize
    let address = StandaloneBlockAdapter::serialize(
        &value,
        &graph_id,
        &key,
        &identity,
        &store,
        "meta/title",
    )
    .await
    .unwrap();

    // Deserialize
    let recovered: String = StandaloneBlockAdapter::deserialize(
        &address,
        &graph_id,
        &key,
        &store,
    )
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
    let recovered: String = TextDocumentAdapter::deserialize(
        &address,
        &graph_id,
        &key,
        &store,
    )
    .await
    .unwrap();

    assert_eq!(text, recovered);
}
