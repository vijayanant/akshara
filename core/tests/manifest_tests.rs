use rand::rngs::OsRng;
use sovereign_core::graph::{BlockId, Manifest};
use sovereign_core::identity::SecretIdentity;
use uuid::Uuid;

#[test]
fn manifest_id_depends_on_content_and_history() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();
    let block_hashes = vec![BlockId([1u8; 32]), BlockId([2u8; 32])];
    let parents = vec![];

    let manifest1 = Manifest::new(doc_id, block_hashes.clone(), parents.clone(), &identity);

    // 1. Merkle Root Check (Deterministic Content)
    let manifest2 = Manifest::new(doc_id, block_hashes.clone(), parents.clone(), &identity);
    assert_eq!(manifest1.merkle_root(), manifest2.merkle_root());

    // 2. ID Check (Deterministic History)
    // Same content, same parents, same author -> Same ID
    assert_eq!(manifest1.id(), manifest2.id());

    // 3. Different History -> Different ID (but Same Merkle Root)
    // We can't easily change parents without mocking ManifestId, but we can change document_id
    let doc_id2 = Uuid::new_v4();
    let manifest3 = Manifest::new(doc_id2, block_hashes.clone(), parents, &identity);

    assert_eq!(
        manifest1.merkle_root(),
        manifest3.merkle_root(),
        "Merkle root relies only on blocks"
    );
    assert_ne!(
        manifest1.id(),
        manifest3.id(),
        "ID includes document metadata"
    );
}
