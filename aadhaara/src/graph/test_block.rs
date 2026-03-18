use rand::rngs::OsRng;

use crate::{BlockId, GraphKey, graph::Block, graph::BlockType, identity::SecretIdentity};

// Helper functions

pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

pub fn create_dummy_key() -> GraphKey {
    GraphKey::generate(&mut OsRng)
}

pub fn create_standard_block(content_data: &[u8]) -> (Block, SecretIdentity) {
    let identity = create_identity();
    let key = create_dummy_key();
    let gid = crate::GraphId::new();
    let block = Block::new(
        gid,
        content_data.to_vec(),
        BlockType::from("p"),
        vec![],
        &key,
        &identity,
    )
    .expect("Failed to create block");
    (block, identity)
}

// --- Identity & Deduplication Tests ---
#[test]
fn block_id_is_deterministic_for_deduplication() {
    let identity = create_identity();
    let key = create_dummy_key();
    let gid = crate::GraphId::new();
    let content = b"data".to_vec();

    let block1 = Block::new(
        gid,
        content.clone(),
        BlockType::from("p"),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    let block2 = Block::new(gid, content, BlockType::from("p"), vec![], &key, &identity).unwrap();

    // DEDUPLICATION RITUAL:
    // Identical content in the same graph results in the same CID,
    // enabling massive storage and sync savings (Pillar 2: Permanence).
    assert_eq!(
        block1.id(),
        block2.id(),
        "Identical content MUST result in identical CIDs for deduplication"
    );
}

#[test]
fn block_adversarial_deduplication_privacy_leak() {
    let identity = create_identity();
    let content = b"Secret Message".to_vec();

    // Same content, different keys (simulating different graphs)
    let key_a = create_dummy_key();
    let key_b = create_dummy_key();

    let gid_a = crate::GraphId::new();
    let gid_b = crate::GraphId::new();

    let block_a = Block::new(
        gid_a,
        content.clone(),
        BlockType::from("p"),
        vec![],
        &key_a,
        &identity,
    )
    .unwrap();
    let block_b = Block::new(
        gid_b,
        content,
        BlockType::from("p"),
        vec![],
        &key_b,
        &identity,
    )
    .unwrap();

    // CRITICAL PRIVACY INVARIANT:
    // Even if the content is identical, the CID must be different if the keys are different.
    // This prevents a Relay from performing "Correlation Attacks" across different private graphs.
    assert_ne!(
        block_a.id(),
        block_b.id(),
        "Blocks from different graphs must have different CIDs even if content is identical"
    );
}

#[test]
fn block_id_is_unique_per_content() {
    let identity = create_identity();
    let key = create_dummy_key();
    let gid = crate::GraphId::new();

    let block1 = Block::new(
        gid,
        b"A".to_vec(),
        BlockType::from("p"),
        vec![],
        &key,
        &identity,
    )
    .unwrap();
    let block2 = Block::new(
        gid,
        b"B".to_vec(),
        BlockType::from("p"),
        vec![],
        &key,
        &identity,
    )
    .unwrap();

    assert_ne!(block1.id(), block2.id());
}

#[test]
fn block_is_signed_by_author() {
    let (block, identity) = create_standard_block(&[1, 2, 3]);
    let public_id = identity.public();

    assert_eq!(block.author(), public_id.signing_key());
    assert!(
        public_id.verify(block.id().as_ref(), block.signature()),
        "Block signature must be valid"
    );
}

// --- Encryption Tests ---

#[test]
fn block_content_encryption_cycle() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let plaintext = b"Sensitive Data".to_vec();
    let graph_key = GraphKey::generate(&mut rng);
    let gid = crate::GraphId::new();

    let block = Block::new(
        gid,
        plaintext.clone(),
        BlockType::from("p"),
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();

    // Verify stored data is ciphertext
    assert_ne!(block.content().as_bytes(), plaintext);

    // Verify decryption
    let decrypted = block.decrypt(&gid, &graph_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

// --- Integrity Tests ---

#[test]
fn block_integrity_check_success() {
    let (block, _) = create_standard_block(&[]);
    assert!(block.verify_integrity().is_ok());
}

#[test]
fn block_integrity_fails_on_tampered_metadata() {
    let (block, _) = create_standard_block(&[]);

    let bytes = crate::base::encoding::to_canonical_bytes(&block).unwrap();

    // Tamper: Manually flip a bit in the CBOR bytes
    let mut fuzzed = bytes.clone();
    let len = fuzzed.len();
    fuzzed[len - 10] ^= 0xFF;

    // In strict mode, this might fail at the decoder level (Syntax error)
    // or at the application level (IntegrityError). Both are valid protections.
    let decode_res: Result<Block, _> = crate::base::encoding::from_canonical_bytes(&fuzzed[..]);
    if let Ok(tampered_block) = decode_res {
        assert!(tampered_block.verify_integrity().is_err());
    }
}

#[test]
fn block_supports_empty_content() {
    let identity = create_identity();
    let key = create_dummy_key();
    let gid = crate::GraphId::new();

    let block = Block::new(gid, vec![], BlockType::from("p"), vec![], &key, &identity).unwrap();
    assert!(block.verify_integrity().is_ok());

    // Decrypt and check
    let decrypted = block.decrypt(&gid, &key).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn block_integrity_fails_on_tampered_signature() {
    let (block, _) = create_standard_block(&[]);

    let mut bytes = crate::base::encoding::to_canonical_bytes(&block).unwrap();

    // Tamper: The signature is near the beginning of the block in our Serde mapping.
    // Flip a bit in the middle of the block to hit metadata or signature.
    bytes[20] ^= 0xFF;

    let tampered_block: Block = serde_ipld_dagcbor::from_slice(&bytes[..]).unwrap();
    assert!(
        tampered_block.verify_integrity().is_err(),
        "Integrity must fail on bad signature or metadata"
    );
}

#[test]
fn block_supports_multiple_parents() {
    let identity = create_identity();
    let key = create_dummy_key();
    let gid = crate::GraphId::new();

    let p1 = BlockId::from_sha256(&[1u8; 32]);
    let p2 = BlockId::from_sha256(&[2u8; 32]);
    let parents = vec![p1, p2];

    let block = Block::new(
        gid,
        vec![],
        BlockType::from("p"),
        parents.clone(),
        &key,
        &identity,
    )
    .unwrap();

    assert_eq!(block.parents().len(), 2);
    assert!(block.verify_integrity().is_ok());
}

#[test]
fn block_restores_from_raw_parts() {
    let (original, _) = create_standard_block(&[10, 20, 30]);

    // Simulate extraction from wire/storage
    let restored = Block::from_raw_parts(
        original.id(),
        original.author().clone(),
        original.signature().clone(),
        original.content().clone(),
        original.block_type().clone(),
        original.parents().to_vec(),
    );

    assert_eq!(restored.id(), original.id());
    assert!(restored.verify_integrity().is_ok());
}
