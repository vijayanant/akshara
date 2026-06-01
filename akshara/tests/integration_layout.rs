use akshara::layout::{BlockLayout, ChunkedLayout, CollectionLayout, StandaloneLayout, TextLayout};
use akshara_aadhaara::{Address, GraphId, GraphKey, GraphStore, InMemoryStore, SecretIdentity};

#[tokio::test]
async fn test_standalone_layout_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let value = "Hello, Standalone World!".to_string();

    // Serialize
    let address =
        StandaloneLayout::serialize(&value, &graph_id, &key, &identity, &store, "meta/title")
            .await
            .unwrap();

    // Deserialize
    let recovered: String = StandaloneLayout::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    assert_eq!(value, recovered);
}

#[tokio::test]
async fn test_text_layout_collaborative_sentence_splitting() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let text = "Clause 1. Clause 2? Clause 3!".to_string();

    // Serialize
    let address =
        TextLayout::serialize(&text, &graph_id, &key, &identity, &store, "content/clauses")
            .await
            .unwrap();

    // Deserialize
    let recovered: String = TextLayout::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    assert_eq!(text, recovered);
}

#[tokio::test]
async fn test_chunked_layout_roundtrip() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Set custom chunk size for quick testing (10 KB)
    ChunkedLayout::set_chunk_size(10 * 1024);

    // Create a 25 KB payload of random bytes (splits into 3 chunks)
    use rand::RngCore;
    let mut data = vec![0u8; 25 * 1024];
    rng.fill_bytes(&mut data);

    // Serialize
    let address =
        ChunkedLayout::serialize(&data, &graph_id, &key, &identity, &store, "payload/data")
            .await
            .unwrap();

    // Deserialize
    let recovered: Vec<u8> = ChunkedLayout::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    // Reset to default chunk size (1 MB) to prevent side effects in other tests
    ChunkedLayout::set_chunk_size(1024 * 1024);

    assert_eq!(data, recovered);
}

#[tokio::test]
async fn test_collection_layout_roundtrip() {
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
    let address = CollectionLayout::serialize(&items, &graph_id, &key, &identity, &store, "items")
        .await
        .unwrap();

    // Deserialize
    let recovered: Vec<String> = CollectionLayout::deserialize(&address, &graph_id, &key, &store)
        .await
        .unwrap();

    assert_eq!(items, recovered);
}

#[tokio::test]
async fn test_layout_decryption_failure() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let wrong_key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let value = "Secret data".to_string();

    let address = StandaloneLayout::serialize(&value, &graph_id, &key, &identity, &store, "secret")
        .await
        .unwrap();

    // Attempt deserialize with wrong key -> should fail with Crypto / Decryption error
    let res: std::result::Result<String, _> =
        StandaloneLayout::deserialize(&address, &graph_id, &wrong_key, &store).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_layout_not_found_failure() {
    let mut rng = rand::rngs::OsRng;
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Create a random block ID and address that is NOT in the store
    let fake_block_id = akshara_aadhaara::BlockId::from_sha256(&[0x99; 32]);
    let address = Address::from(fake_block_id);

    // Attempt deserialize -> should fail because block is not found
    let res: std::result::Result<String, _> =
        StandaloneLayout::deserialize(&address, &graph_id, &key, &store).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_layout_type_mismatch_failure() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Create a manifest address (which has CODEC_AKSHARA_MANIFEST instead of CODEC_AKSHARA_BLOCK)
    let content_root = akshara_aadhaara::BlockId::from_sha256(&[0x11; 32]);
    let manifest = akshara_aadhaara::Manifest::new(
        graph_id,
        content_root,
        vec![],
        akshara_aadhaara::ManifestId::null(),
        Address::null(),
        &identity,
        None,
    );
    let address = Address::from(manifest.id());

    // Attempt deserialize -> should fail because of codec/type mismatch
    let res: std::result::Result<String, _> =
        StandaloneLayout::deserialize(&address, &graph_id, &key, &store).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_text_layout_malformed_index_failure() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Write malformed CBOR content as the index block (e.g. just raw bytes of a string instead of BTreeMap)
    let malformed_index_data =
        akshara_aadhaara::to_canonical_bytes(&"Not a BTreeMap".to_string()).unwrap();
    let block = akshara_aadhaara::Block::new(
        graph_id,
        malformed_index_data,
        akshara_aadhaara::BlockType::AksharaIndexV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let address = Address::from(block.id());

    // TextLayout::deserialize expects a BTreeMap index, so it should fail
    let res: std::result::Result<String, _> =
        TextLayout::deserialize(&address, &graph_id, &key, &store).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_chunked_layout_malformed_index_failure() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Write malformed CBOR (e.g. just a String) instead of Vec<Address> for chunked index
    let malformed_index_data =
        akshara_aadhaara::to_canonical_bytes(&"Not a Vec".to_string()).unwrap();
    let block = akshara_aadhaara::Block::new(
        graph_id,
        malformed_index_data,
        akshara_aadhaara::BlockType::AksharaIndexV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let address = Address::from(block.id());

    let res: std::result::Result<Vec<u8>, _> =
        ChunkedLayout::deserialize(&address, &graph_id, &key, &store).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_collection_layout_malformed_index_failure() {
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // Write malformed CBOR (e.g. just a String) instead of BTreeMap<String, Address>
    let malformed_index_data =
        akshara_aadhaara::to_canonical_bytes(&"Not a BTreeMap".to_string()).unwrap();
    let block = akshara_aadhaara::Block::new(
        graph_id,
        malformed_index_data,
        akshara_aadhaara::BlockType::AksharaIndexV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&block).await.unwrap();

    let address = Address::from(block.id());

    let res: std::result::Result<Vec<String>, _> =
        CollectionLayout::deserialize(&address, &graph_id, &key, &store).await;
    assert!(res.is_err());
}
