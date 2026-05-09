use crate::base::address::{Address, BlockId};
use crate::graph::Manifest;
use crate::graph::document::{AksharaDocument, BlockMode, DocumentSchema, FieldDescriptor};
use crate::test_utils::TestFactory;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct TestMolecule {
    pub title: String,
    pub body: Vec<u8>,
}

/// Manually implementing the trait as the macro would.
impl AksharaDocument for TestMolecule {
    fn schema() -> DocumentSchema {
        DocumentSchema {
            type_name: "TestMolecule".to_string(),
            version: 1,
            fields: vec![
                FieldDescriptor {
                    path: "meta/title".to_string(),
                    mode: BlockMode::Block,
                    is_lazy: false,
                },
                FieldDescriptor {
                    path: "content/body".to_string(),
                    mode: BlockMode::Block,
                    is_lazy: true,
                },
            ],
        }
    }
}

#[tokio::test]
async fn test_molecule_trait_rituals() {
    let molecule = TestMolecule {
        title: "Hello".to_string(),
        body: b"World".to_vec(),
    };

    // 1. Verify Schema
    let schema = TestMolecule::schema();
    assert_eq!(schema.type_name, "TestMolecule");
    assert_eq!(schema.fields.len(), 2);

    // 2. Verify Serialization Round-trip
    let bytes = molecule.to_bytes().unwrap();
    let recovered = TestMolecule::from_bytes(&bytes).unwrap();
    assert_eq!(molecule, recovered);

    // 3. Verify Lazy Path Discovery
    let lazy = TestMolecule::lazy_paths();
    assert_eq!(lazy.len(), 1);
    assert_eq!(lazy[0], "content/body");
}

#[tokio::test]
async fn test_manifest_schema_anchoring() {
    let factory = TestFactory::new().await;

    // Create a dummy schema anchor (normally this would be a real schema block CID)
    let schema_anchor = Address::from(BlockId::from_sha256(&[0x55; 32]));

    let manifest = Manifest::new(
        factory.graph_id,
        factory.dummy_root(),
        vec![],
        factory.anchor,
        schema_anchor, // The new field
        &factory.identity,
        None,
    );

    // Verify retrieval
    assert_eq!(manifest.schema_anchor(), schema_anchor);

    // Verify CID binding (Changing schema anchor must change Manifest ID)
    let different_schema = Address::from(BlockId::from_sha256(&[0x66; 32]));
    let manifest_alt = Manifest::new(
        factory.graph_id,
        factory.dummy_root(),
        vec![],
        factory.anchor,
        different_schema,
        &factory.identity,
        None,
    );

    assert_ne!(
        manifest.id(),
        manifest_alt.id(),
        "Manifest ID must be bound to its schema anchor"
    );
}
