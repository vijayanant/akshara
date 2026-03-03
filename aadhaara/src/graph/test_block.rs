use rand::rngs::OsRng;

use crate::{BlockId, GraphKey, graph::Block, identity::SecretIdentity};

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
    let block = Block::new(
        content_data.to_vec(),
        "p".to_string(),
        vec![],
        &key,
        &identity,
    )
    .expect("Failed to create block");
    (block, identity)
}

// --- Identity & Randomness Tests ---

#[test]
fn block_id_is_unique_due_to_random_nonce() {
    let identity = create_identity();
    let key = create_dummy_key();
    let content = b"data".to_vec();

    let block1 = Block::new(content.clone(), "p".to_string(), vec![], &key, &identity).unwrap();
    let block2 = Block::new(content, "p".to_string(), vec![], &key, &identity).unwrap();

    // Since each block generation now uses a random 96-bit nonce,
    // identical content MUST result in different CIDs to ensure cryptographic safety (AES-GCM).
    assert_ne!(
        block1.id(),
        block2.id(),
        "Identical content must have different IDs due to unique nonces"
    );
}

#[test]
fn block_id_is_unique_per_content() {
    let identity = create_identity();
    let key = create_dummy_key();

    let block1 = Block::new(b"A".to_vec(), "p".to_string(), vec![], &key, &identity).unwrap();
    let block2 = Block::new(b"B".to_vec(), "p".to_string(), vec![], &key, &identity).unwrap();

    assert_ne!(block1.id(), block2.id());
}

// --- Authorization Tests ---

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

    let block = Block::new(
        plaintext.clone(),
        "p".to_string(),
        vec![],
        &graph_key,
        &identity,
    )
    .unwrap();

    // Verify stored data is ciphertext
    assert_ne!(block.content().as_bytes(), plaintext);

    // Verify decryption
    let decrypted = block.content().decrypt(&graph_key).unwrap();
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

    let bytes = serde_ipld_dagcbor::to_vec(&block).unwrap();

    // Tamper: Manually flip a bit in the CBOR bytes
    let mut fuzzed = bytes.clone();
    let len = fuzzed.len();
    fuzzed[len - 10] ^= 0xFF;

    // In strict mode, this might fail at the decoder level (Syntax error)
    // or at the application level (IntegrityError). Both are valid protections.
    let decode_res: Result<Block, _> = serde_ipld_dagcbor::from_slice(&fuzzed[..]);

    if let Ok(tampered_block) = decode_res {
        assert!(tampered_block.verify_integrity().is_err());
    }
}

#[test]
fn block_supports_empty_content() {
    let identity = create_identity();
    let key = create_dummy_key();

    let block = Block::new(vec![], "p".to_string(), vec![], &key, &identity).unwrap();
    assert!(block.verify_integrity().is_ok());

    // Decrypt and check
    let decrypted = block.content().decrypt(&key).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn block_integrity_fails_on_tampered_signature() {
    let (block, _) = create_standard_block(&[]);

    let mut bytes = serde_ipld_dagcbor::to_vec(&block).unwrap();

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

    let p1 = BlockId::from_sha256(&[1u8; 32]);
    let p2 = BlockId::from_sha256(&[2u8; 32]);
    let parents = vec![p1, p2];

    let block = Block::new(vec![], "p".to_string(), parents.clone(), &key, &identity).unwrap();

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
        original.block_type().to_string(),
        original.parents().to_vec(),
    );

    assert_eq!(restored.id(), original.id());
    assert!(restored.verify_integrity().is_ok());
}
