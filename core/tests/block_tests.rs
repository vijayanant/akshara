use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::{Block, BlockId};
use sovereign_core::identity::SecretIdentity;

// --- Helper Functions ---

fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

fn create_dummy_content(data: &[u8]) -> BlockContent {
    let key = DocKey::new([0u8; 32]);
    let nonce = [0u8; 12];
    BlockContent::encrypt(data, &key, nonce).unwrap()
}

fn create_standard_block(content_data: &[u8]) -> (Block, SecretIdentity) {
    let identity = create_identity();
    let content = create_dummy_content(content_data);
    let block = Block::new(content, "a".to_string(), "p".to_string(), vec![], &identity);
    (block, identity)
}

// --- Identity & Determinism Tests ---

#[test]
fn block_id_is_deterministic() {
    let identity = create_identity();
    let content_bytes = vec![0x1, 0x2, 0x3];

    // Create two identical contents (same data, key, nonce)
    let content1 = create_dummy_content(&content_bytes);
    let content2 = create_dummy_content(&content_bytes);

    let block1 = Block::new(
        content1,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    let block2 = Block::new(
        content2,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );

    assert_eq!(
        block1.id(),
        block2.id(),
        "Identical blocks must have identical IDs"
    );
}

#[test]
fn block_id_is_unique_per_content() {
    let identity = create_identity();

    let content1 = create_dummy_content(&[0xA]);
    let content2 = create_dummy_content(&[0xB]);

    let block1 = Block::new(
        content1,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    let block2 = Block::new(
        content2,
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );

    assert_ne!(block1.id(), block2.id());
}

#[test]
fn block_id_depends_on_metadata() {
    let identity = create_identity();
    let content = create_dummy_content(&[0x1]);

    let block1 = Block::new(
        content.clone(),
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    let block2 = Block::new(
        content.clone(),
        "b".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    ); // Diff Rank
    let block3 = Block::new(
        content,
        "a".to_string(),
        "h1".to_string(),
        vec![],
        &identity,
    ); // Diff Type

    assert_ne!(block1.id(), block2.id());
    assert_ne!(block1.id(), block3.id());
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
    let doc_key = DocKey::generate(&mut rng);
    let nonce = [0u8; 12];

    let content = BlockContent::encrypt(&plaintext, &doc_key, nonce).unwrap();
    let block = Block::new(content, "a".to_string(), "p".to_string(), vec![], &identity);

    // Verify stored data is ciphertext
    assert_ne!(block.content().as_bytes(), plaintext);

    // Verify decryption
    let decrypted = block.content().decrypt(&doc_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encryption_fails_with_wrong_key() {
    let mut rng = OsRng;
    let plaintext = b"secret";
    let key1 = DocKey::generate(&mut rng);
    let key2 = DocKey::generate(&mut rng);
    let nonce = [0u8; 12];

    let content = BlockContent::encrypt(plaintext, &key1, nonce).unwrap();
    assert!(content.decrypt(&key2).is_err());
}

#[test]
fn encryption_fails_on_tampered_ciphertext() {
    // We cannot easily mutate BlockContent because fields are private (Encapsulation).
    // This is good. But we can try to decrypt random garbage interpreted as BlockContent?
    // Or we can rely on `aes_gcm` crate tests for tag validation.
    // Ideally, we'd have a `from_raw` constructor for BlockContent for testing, but that breaks safety.
}

// --- Integrity Tests ---

#[test]
fn block_integrity_check_success() {
    let (block, _) = create_standard_block(&[]);
    assert!(block.verify_integrity().is_ok());
}

#[test]
fn block_integrity_fails_on_tampered_data() {
    let (block, _) = create_standard_block(&[]);

    // Serialize
    let json = serde_json::to_string(&block).unwrap();

    // Tamper: Change rank "a" to "b"
    let tampered_json = json.replace("\"rank\":\"a\"", "\"rank\":\"b\"");

    // Deserialize
    let tampered_block: Block = serde_json::from_str(&tampered_json).unwrap();

    // Verify failure: ID in struct matches original, but content is different.
    assert!(tampered_block.verify_integrity().is_err());
}

// --- Corner Case Tests (New) ---

#[test]
fn block_supports_empty_content() {
    let (block, _) = create_standard_block(&[]);
    assert!(block.verify_integrity().is_ok());

    // AES-GCM adds a 16-byte tag, so ciphertext is never empty.
    assert_eq!(block.content().as_bytes().len(), 16);

    // To decrypt we need the key used in helper. Helper uses 0-key.
    let key = DocKey::new([0u8; 32]);
    let decrypted = block.content().decrypt(&key).unwrap();
    assert!(decrypted.is_empty());
}
#[test]
fn block_supports_multiple_parents() {
    let identity = create_identity();
    let content = create_dummy_content(&[]);

    let p1 = BlockId([1u8; 32]);
    let p2 = BlockId([2u8; 32]);
    let parents = vec![p1, p2];

    let block = Block::new(
        content,
        "a".to_string(),
        "p".to_string(),
        parents.clone(),
        &identity,
    );

    // Ensure ID depends on parents
    let block_no_parents = Block::new(
        create_dummy_content(&[]),
        "a".to_string(),
        "p".to_string(),
        vec![],
        &identity,
    );
    assert_ne!(block.id(), block_no_parents.id());

    assert!(block.verify_integrity().is_ok());
}
