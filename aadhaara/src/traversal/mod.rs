pub mod auditor;
pub mod index_builder;
pub mod walker;

pub use auditor::Auditor;
pub use index_builder::IndexBuilder;
pub use walker::{BlockWalker, GraphWalker};

#[cfg(test)]
mod test_auditor;

#[cfg(test)]
mod test_index_builder;

#[cfg(test)]
mod test_traversal;

#[cfg(test)]
mod test_merkle_index;

// --- Internal Test Helpers ---
// Strictly isolated to testing to ensure zero unwrap() in production.

#[cfg(test)]
pub(crate) fn create_identity() -> crate::identity::SecretIdentity {
    let mut rng = rand::rngs::OsRng;
    crate::identity::SecretIdentity::generate(&mut rng).unwrap()
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
    store: &crate::state::in_memory_store::InMemoryStore,
    identity: &crate::identity::SecretIdentity,
) -> crate::base::address::ManifestId {
    use crate::test_utils::TestFactory;
    use std::sync::Arc;
    let mut factory = TestFactory::new().await;
    factory.identity = identity.clone();
    factory.store = Arc::new(store.clone()); // Use the PROVIDED store

    factory.anchor = factory.create_identity_anchor().await;
    factory.anchor
}

#[cfg(test)]
pub(crate) async fn create_chain(
    length: usize,
    store: &crate::state::in_memory_store::InMemoryStore,
) -> (
    Vec<crate::base::address::ManifestId>,
    crate::base::crypto::SigningPublicKey,
) {
    use crate::test_utils::TestFactory;
    use std::sync::Arc;
    let mut factory = TestFactory::new().await;
    factory.store = Arc::new(store.clone()); // Use the PROVIDED store
    factory.anchor = factory.create_identity_anchor().await;

    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest = factory
            .create_manifest(factory.dummy_root(), parents.clone())
            .await;
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    (ids, factory.identity.public().signing_key().clone())
}
