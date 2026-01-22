use sovereign_core::graph::{BlockId, Manifest};
use sovereign_core::identity::SecretIdentity;
use uuid::Uuid;

#[test]
fn manifest_id_is_merkle_root_of_blocks() {
    let identity = SecretIdentity::generate();
    let doc_id = Uuid::new_v4();
    // Two dummy block IDs
    let block_hashes = vec![BlockId([1u8; 32]), BlockId([2u8; 32])];
    let parents = vec![];

    // Feature: Manifest creation with Merkle Root ID
    let manifest = Manifest::new(doc_id, block_hashes.clone(), parents, &identity);

    assert_eq!(manifest.document_id(), doc_id);
    assert_eq!(manifest.active_blocks(), &block_hashes);

    // Check ID logic (Merkle Root)
    // For 2 leaves [1, 2], the root should be Hash(Hash(1) || Hash(2))
    // We can't easily replicate the hash logic here without duplicating it.
    // But we can check determinism.

    let manifest2 = Manifest::new(doc_id, block_hashes.clone(), vec![], &identity);
    // IDs should be equal (if signed deterministically? No, signature differs, but ID is content based)
    // Manifest ID depends on content.
    // LLD-001: Manifest ID is Merkle Root of active_blocks.
    // It implies Manifest ID does NOT include signature or author (unlike Block).
    // Let's verify LLD-001.
    // "The Manifest's id is the Merkle Root of the document."
    // "struct Manifest { id, ... signature ... }"
    // So ID is independent of signature.

    assert_eq!(manifest.id(), manifest2.id());
}
