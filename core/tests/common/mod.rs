use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, DocKey, Lockbox};
use sovereign_core::graph::{Block, DocId, Manifest, ManifestId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

#[allow(dead_code)]
pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

#[allow(dead_code)]
pub fn create_dummy_content(data: &[u8]) -> BlockContent {
    let key = DocKey::new([0u8; 32]);
    let nonce = [0u8; 12];
    BlockContent::encrypt(data, &key, nonce).unwrap()
}

#[allow(dead_code)]
pub fn create_standard_block(content_data: &[u8]) -> (Block, SecretIdentity) {
    let identity = create_identity();
    let content = create_dummy_content(content_data);
    let block = Block::new(content, "a".to_string(), "p".to_string(), vec![], &identity);
    (block, identity)
}

#[allow(dead_code)]
pub fn create_chain(length: usize, store: &mut InMemoryStore) -> Vec<ManifestId> {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = DocId::new();
    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest = Manifest::new(doc_id, vec![], parents.clone(), &identity);
        store.put_manifest(&manifest).unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    ids
}

#[allow(dead_code)]
pub fn create_lockbox(recipient: &SecretIdentity) -> (Lockbox, DocKey) {
    let mut rng = OsRng;
    let doc_key = DocKey::generate(&mut rng);
    let lockbox = Lockbox::create(recipient.public().encryption_key(), &doc_key, &mut rng)
        .expect("Lockbox creation failed");
    (lockbox, doc_key)
}
