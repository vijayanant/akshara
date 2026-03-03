pub mod auditor;
pub mod index_builder;
pub mod walker;

pub use auditor::Auditor;
pub use index_builder::IndexBuilder;
pub use walker::{BlockWalker, GraphWalker};

#[cfg(test)]
mod test_traversal;

#[cfg(test)]
mod test_merkle_index;

// --- Internal Test Helpers ---
// Strictly isolated to testing to ensure zero unwrap() in production.

#[cfg(test)]
pub(crate) fn create_identity() -> crate::identity::SecretIdentity {
    let mut rng = rand::rngs::OsRng;
    crate::identity::SecretIdentity::generate(&mut rng)
}

#[cfg(test)]
pub(crate) fn create_dummy_key() -> crate::base::crypto::GraphKey {
    crate::base::crypto::GraphKey::generate(&mut rand::rngs::OsRng)
}

#[cfg(test)]
pub(crate) fn create_dummy_root() -> crate::base::address::BlockId {
    crate::base::address::BlockId::from_sha256(&[0xFFu8; 32])
}

#[cfg(test)]
pub(crate) async fn create_valid_anchor(
    store: &mut crate::state::in_memory_store::InMemoryStore,
    identity: &crate::identity::SecretIdentity,
) -> crate::base::address::ManifestId {
    use crate::graph::BlockType;
    use crate::state::store::GraphStore;
    use std::collections::BTreeMap;

    let identity_key = crate::base::crypto::GraphKey::new([0u8; 32]);
    let mut credentials_map = BTreeMap::new();
    let signer_hex = identity.public().signing_key().to_hex();

    // Create an authorization block for the identity itself (Genesis authorization)
    let auth_block = crate::graph::Block::new(
        vec![],
        BlockType::AksharaAuthV1,
        vec![],
        &identity_key,
        identity,
    )
    .unwrap();
    store.put_block(&auth_block).await.unwrap();

    // Put it in the /credentials/ path as per SPEC
    credentials_map.insert(
        signer_hex,
        crate::base::address::Address::from(auth_block.id()),
    );

    let mut root_map = BTreeMap::new();
    let credentials_bytes = crate::base::encoding::to_canonical_bytes(&credentials_map).unwrap();

    let credentials_index = crate::graph::Block::new(
        credentials_bytes,
        BlockType::AksharaIndexV1,
        vec![],
        &identity_key,
        identity,
    )
    .unwrap();
    store.put_block(&credentials_index).await.unwrap();

    root_map.insert(
        "credentials".to_string(),
        crate::base::address::Address::from(credentials_index.id()),
    );

    let root_bytes = crate::base::encoding::to_canonical_bytes(&root_map).unwrap();

    let genesis_index = crate::graph::Block::new(
        root_bytes,
        BlockType::AksharaIndexV1,
        vec![],
        &identity_key,
        identity,
    )
    .unwrap();
    store.put_block(&genesis_index).await.unwrap();

    let null_id = crate::base::address::ManifestId::from_sha256(&[0x00; 32]);
    let genesis_manifest = crate::graph::Manifest::new(
        crate::base::address::GraphId::new(),
        genesis_index.id(),
        vec![],
        null_id,
        identity,
    );

    store.put_manifest(&genesis_manifest).await.unwrap();
    genesis_manifest.id()
}

#[cfg(test)]
pub(crate) async fn create_chain(
    length: usize,
    store: &mut crate::state::in_memory_store::InMemoryStore,
) -> (
    Vec<crate::base::address::ManifestId>,
    crate::base::crypto::SigningPublicKey,
) {
    use crate::state::store::GraphStore;
    let mut rng = rand::rngs::OsRng;
    let identity = crate::identity::SecretIdentity::generate(&mut rng);
    let graph_id = crate::base::address::GraphId::new();
    let root = create_dummy_root();

    let anchor = create_valid_anchor(store, &identity).await;

    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest =
            crate::graph::Manifest::new(graph_id, root, parents.clone(), anchor, &identity);
        store.put_manifest(&manifest).await.unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    (ids, identity.public().signing_key().clone())
}
