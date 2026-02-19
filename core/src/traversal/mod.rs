pub mod auditor;
pub mod walker;

pub use auditor::Auditor;
pub use walker::{BlockWalker, GraphWalker};

#[cfg(test)]
mod test_traversal;

#[cfg(test)]
mod test_merkle_index;

// --- Internal Test Helpers ---
// Strictly isolated to testing to ensure zero unwrap() in production.

#[cfg(test)]
pub(crate) fn create_identity() -> crate::identity::SecretIdentity {
    crate::identity::SecretIdentity::generate(&mut rand::rngs::OsRng)
}

#[cfg(test)]
pub(crate) fn create_dummy_key() -> crate::base::crypto::GraphKey {
    crate::base::crypto::GraphKey::generate(&mut rand::rngs::OsRng)
}

#[cfg(test)]
pub(crate) fn create_dummy_anchor() -> crate::base::address::ManifestId {
    crate::base::address::ManifestId::from_sha256(&[0u8; 32])
}

#[cfg(test)]
pub(crate) fn create_dummy_root() -> crate::base::address::BlockId {
    crate::base::address::BlockId::from_sha256(&[0xFFu8; 32])
}

#[cfg(test)]
pub(crate) fn create_chain(
    length: usize,
    store: &mut crate::state::in_memory_store::InMemoryStore,
) -> Vec<crate::base::address::ManifestId> {
    use crate::state::store::GraphStore;
    let mut rng = rand::rngs::OsRng;
    let identity = crate::identity::SecretIdentity::generate(&mut rng);
    let graph_id = crate::base::address::GraphId::new();
    let anchor = create_dummy_anchor();
    let root = create_dummy_root();

    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest =
            crate::graph::Manifest::new(graph_id, root, parents.clone(), anchor, &identity);
        store.put_manifest(&manifest).unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    ids
}
