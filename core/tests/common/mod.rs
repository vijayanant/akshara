use rand::rngs::OsRng;
use sovereign_core::crypto::{BlockContent, GraphKey};
use sovereign_core::graph::{Block, BlockId, GraphId, Manifest, ManifestId};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

#[allow(dead_code)]
pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

#[allow(dead_code)]
pub fn create_dummy_key() -> GraphKey {
    GraphKey::generate(&mut OsRng)
}

#[allow(dead_code)]
pub fn create_dummy_anchor() -> ManifestId {
    ManifestId::from_sha256(&[0u8; 32])
}

#[allow(dead_code)]
pub fn create_dummy_root() -> BlockId {
    BlockId::from_sha256(&[0xFFu8; 32])
}

#[allow(dead_code)]
pub fn create_dummy_content(data: &[u8]) -> BlockContent {
    let key = GraphKey::from([0u8; 32]);
    let nonce = [0u8; 12];
    BlockContent::encrypt(data, &key, nonce).unwrap()
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn create_chain(length: usize, store: &mut InMemoryStore) -> Vec<ManifestId> {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let anchor = create_dummy_anchor();
    let root = create_dummy_root();

    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest = Manifest::new(graph_id, root, parents.clone(), anchor, &identity);
        store.put_manifest(&manifest).unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    ids
}
