use akshara::AksharaDocument as AksharaDocumentMacro;
use akshara_aadhaara::{AksharaDocument, BlockMode};

#[derive(AksharaDocumentMacro, serde::Serialize, serde::Deserialize)]
struct Patient {
    pub name: String,
    #[lazy]
    pub medical_history: String,
    #[collection]
    pub consultations: Vec<String>,
}

#[tokio::test]
async fn test_derive_macro_generates_correct_schema() {
    // 1. Verify that the trait was implemented automatically
    let schema = Patient::schema();

    assert_eq!(schema.type_name, "Patient");
    assert_eq!(schema.fields.len(), 3);

    // 2. Verify individual field physical modes
    let name_field = schema.fields.iter().find(|f| f.path == "name").unwrap();
    assert_eq!(name_field.mode, BlockMode::Block);
    assert!(!name_field.is_lazy);

    let history_field = schema
        .fields
        .iter()
        .find(|f| f.path == "medical_history")
        .unwrap();
    assert_eq!(history_field.mode, BlockMode::Block);
    assert!(history_field.is_lazy);

    let consult_field = schema
        .fields
        .iter()
        .find(|f| f.path == "consultations")
        .unwrap();
    assert_eq!(consult_field.mode, BlockMode::Collection);
}
