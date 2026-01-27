use rand::rngs::OsRng;
use sovereign_core::graph::{DocId, Manifest};
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

#[test]
fn store_can_save_and_load_manifest() {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let doc_id = DocId::new();
    let manifest = Manifest::new(doc_id, vec![], vec![], &identity);

    let mut store = InMemoryStore::new();
    store.put_manifest(&manifest).expect("Save failed");

    let loaded = store
        .get_manifest(&manifest.id())
        .expect("Load failed")
        .expect("Manifest not found");

    assert_eq!(loaded.id(), manifest.id());
}
