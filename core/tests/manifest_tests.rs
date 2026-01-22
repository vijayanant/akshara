use rand::rngs::OsRng;
use sovereign_core::graph::{BlockId, Manifest, ManifestId};
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
    assert_eq!(manifest1.id(), manifest2.id());

    // 3. Different History -> Different ID (but Same Merkle Root)
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

#[test]
fn manifest_merkle_root_boundary_conditions() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();

    // Case 1: Empty blocks
    let m_empty = Manifest::new(doc_id, vec![], vec![], &identity);
    assert_eq!(m_empty.merkle_root().as_ref(), &[0u8; 32]);

    // Case 2: Single block
    let b1 = BlockId([1u8; 32]);
    let m_single = Manifest::new(doc_id, vec![b1], vec![], &identity);
    assert_eq!(
        m_single.merkle_root().as_ref(),
        b1.as_ref(),
        "Single block root is the block ID itself"
    );

    // Case 3: Odd number of blocks (3)
    let b2 = BlockId([2u8; 32]);
    let b3 = BlockId([3u8; 32]);
    let m_odd = Manifest::new(doc_id, vec![b1, b2, b3], vec![], &identity);
    assert_ne!(m_odd.merkle_root().as_ref(), &[0u8; 32]);
}

#[test]
fn manifest_with_multiple_parents() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = Uuid::new_v4();

    let p1 = ManifestId([0xA1; 32]);
    let p2 = ManifestId([0xA2; 32]);

    let manifest = Manifest::new(doc_id, vec![], vec![p1, p2], &identity);

    assert_eq!(manifest.parents().len(), 2);
    assert_eq!(manifest.parents()[0], p1);
    assert_eq!(manifest.parents()[1], p2);
}
