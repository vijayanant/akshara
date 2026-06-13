#![allow(clippy::too_many_lines)]

use akshara::schema::{AksharaDocument, BlockMode, DocumentSchema, FieldDescriptor, LazyField};
use akshara_aadhaara::{
    Address, BlockId, GraphId, GraphKey, GraphStore, InMemoryStore, SecretIdentity,
};
use serde::{Deserialize, Serialize};

// 1. Test LazyField unit behavior
#[test]
fn test_lazy_field_unit() {
    let mut lf: LazyField<String> = LazyField::new("meta/title".to_string());
    assert_eq!(lf.path(), "meta/title");
    assert!(lf.address().is_none());

    let addr = Address::from(BlockId::from_sha256(&[0xaa; 32]));
    lf.set_address(addr);
    assert_eq!(lf.address(), Some(&addr));
}

// 2. Test manual AksharaDocument implementation (tests default implementations)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct ManualDoc {
    pub value: String,
}

#[async_trait::async_trait]
impl AksharaDocument for ManualDoc {
    fn schema() -> DocumentSchema {
        DocumentSchema {
            type_name: "ManualDoc".to_string(),
            version: 1,
            fields: vec![FieldDescriptor {
                path: "value".to_string(),
                mode: BlockMode::Block,
                is_lazy: false,
            }],
        }
    }
}

#[tokio::test]
async fn test_manual_document_defaults() {
    let doc = ManualDoc {
        value: "hello".to_string(),
    };

    // Test default to_bytes and from_bytes
    let bytes = doc.to_bytes().unwrap();
    let recovered = ManualDoc::from_bytes(&bytes).unwrap();
    assert_eq!(doc, recovered);

    // Test default serialize_fields and deserialize_fields
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let fields = doc
        .serialize_fields(&graph_id, &key, &identity, &store, "doc")
        .await
        .unwrap();
    assert!(fields.is_empty());

    let mut doc_mut = doc.clone();
    let content_root = BlockId::from_sha256(&[0x11; 32]);
    let res = doc_mut
        .deserialize_fields(&graph_id, &key, &store, "doc", &content_root)
        .await;
    assert!(res.is_ok());

    // Test default lazy_paths
    assert!(ManualDoc::lazy_paths().is_empty());
}

// 3. Test derived AksharaDocument with LazyField
#[derive(AksharaDocument, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct LazyDoc {
    pub title: String,
    #[lazy]
    pub details: LazyField<String>,
}

#[tokio::test]
async fn test_derived_document_with_lazy_field() {
    let schema = LazyDoc::schema();
    assert_eq!(schema.type_name, "LazyDoc");
    assert_eq!(schema.fields.len(), 2);

    let title_field = schema.fields.iter().find(|f| f.path == "title").unwrap();
    assert_eq!(title_field.mode, BlockMode::Block);
    assert!(!title_field.is_lazy);

    let details_field = schema.fields.iter().find(|f| f.path == "details").unwrap();
    assert_eq!(details_field.mode, BlockMode::Block);
    assert!(details_field.is_lazy);

    let lazy_paths = LazyDoc::lazy_paths();
    assert_eq!(lazy_paths, vec!["details".to_string()]);

    // Test serialize/deserialize fields behavior
    let mut rng = rand::rngs::OsRng;
    let identity = SecretIdentity::generate(&mut rng).unwrap();
    let graph_id = GraphId::new();
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    let doc = LazyDoc {
        title: "Subject".to_string(),
        details: LazyField::new("details".to_string()),
    };

    // serialize_fields should serialize non-lazy fields only (in this case, 'title')
    let fields = doc
        .serialize_fields(&graph_id, &key, &identity, &store, "/doc_path")
        .await
        .unwrap();

    // Check that 'title' is serialized but not 'details'
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "title");

    // Let's verify that the serialized block of 'title' actually exists in store
    let title_address = fields[0].1;
    let title_block_id = BlockId::try_from(title_address).unwrap();
    let title_block = store.get_block(&title_block_id).await.unwrap().unwrap();
    let decrypted_title: String = title_block
        .decrypt(&graph_id, &key)
        .and_then(|pt| akshara_aadhaara::from_canonical_bytes::<String>(&pt))
        .unwrap();
    assert_eq!(decrypted_title, "Subject");

    // Now let's simulate path resolution for deserialize_fields
    let mut recovered_doc = doc.clone();
    let dummy_root = BlockId::from_sha256(&[0x99; 32]);
    // Path resolution fails, so address remains None
    recovered_doc
        .deserialize_fields(&graph_id, &key, &store, "/doc_path", &dummy_root)
        .await
        .unwrap();
    assert!(recovered_doc.details.address().is_none());

    // Now let's set up the store so resolve_path succeeds
    let details_val = "Here are the secret details.".to_string();
    let details_bytes = akshara_aadhaara::to_canonical_bytes(&details_val).unwrap();
    let details_block = akshara_aadhaara::Block::new(
        graph_id,
        details_bytes,
        akshara_aadhaara::BlockType::AksharaDataV1,
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    store.put_block(&details_block).await.unwrap();

    let mut index_builder = akshara_aadhaara::IndexBuilder::new();
    index_builder
        .insert("/doc_path/details", Address::from(details_block.id()))
        .unwrap();
    index_builder
        .insert("/doc_path/title", title_address)
        .unwrap();

    let root_index_id = index_builder
        .build(graph_id, &store, &identity, &key)
        .await
        .unwrap();

    // Now deserialize_fields should resolve the lazy field address!
    recovered_doc
        .deserialize_fields(&graph_id, &key, &store, "/doc_path", &root_index_id)
        .await
        .unwrap();

    assert_eq!(
        recovered_doc.details.address(),
        Some(&Address::from(details_block.id()))
    );
}
