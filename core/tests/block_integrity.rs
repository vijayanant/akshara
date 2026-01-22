use sovereign_core::crypto::{BlockContent, DocKey};
use sovereign_core::graph::Block;
use sovereign_core::identity::SecretIdentity;

#[test]
fn block_integrity_check_success() {
    let id = SecretIdentity::generate();
    let key = DocKey::new([0u8; 32]);
    let content = BlockContent::encrypt(&[], &key, [0u8; 12]).unwrap();
    let block = Block::new(content, "a".to_string(), "p".to_string(), vec![], &id);

    assert!(block.verify_integrity().is_ok());
}

#[test]
fn block_integrity_fails_on_tampered_rank() {
    let id = SecretIdentity::generate();
    let key = DocKey::new([0u8; 32]);
    let content = BlockContent::encrypt(&[], &key, [0u8; 12]).unwrap();
    let block = Block::new(content, "rank_a".to_string(), "p".to_string(), vec![], &id);

    let json = serde_json::to_string(&block).unwrap();
    // Tamper with rank
    let tampered_json = json.replace("rank_a", "rank_b");

    let tampered_block: Block = serde_json::from_str(&tampered_json).unwrap();

    // Integrity check should detect the mismatch between stored ID/Signature and actual content
    assert!(tampered_block.verify_integrity().is_err());
}
