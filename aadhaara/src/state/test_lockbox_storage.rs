use crate::base::address::GraphId;
use crate::base::crypto::Lockbox;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::{create_dummy_key, create_identity};

#[tokio::test]
async fn store_can_save_and_load_lockboxes() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    let _alice = create_identity();
    let bob = create_identity();
    let graph_id = GraphId::new();
    let graph_key = create_dummy_key();

    let lockbox = Lockbox::create(bob.public().encryption_key(), &graph_key, &mut rng).unwrap();

    store
        .put_lockbox(graph_id, bob.public().signing_key(), &lockbox)
        .await
        .expect("Save lockbox failed");

    let retrieved = store
        .get_lockboxes_for_recipient(bob.public().signing_key())
        .await
        .expect("Fetch lockbox failed");

    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].0, graph_id);
}

#[tokio::test]
async fn store_returns_empty_for_unknown_recipient() {
    let store = InMemoryStore::new();
    let bob = create_identity();

    let retrieved = store
        .get_lockboxes_for_recipient(bob.public().signing_key())
        .await
        .expect("Fetch failed");

    assert!(retrieved.is_empty());
}

#[tokio::test]
async fn store_isolates_recipients() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    let alice = create_identity();
    let bob = create_identity();
    let graph_id = GraphId::new();
    let key = create_dummy_key();

    let lockbox = Lockbox::create(alice.public().encryption_key(), &key, &mut rng).unwrap();
    store
        .put_lockbox(graph_id, alice.public().signing_key(), &lockbox)
        .await
        .unwrap();

    let bob_view = store
        .get_lockboxes_for_recipient(bob.public().signing_key())
        .await
        .unwrap();
    assert!(bob_view.is_empty());
}

#[tokio::test]
async fn store_handles_multiple_lockboxes_for_same_recipient() {
    let mut store = InMemoryStore::new();
    let mut rng = rand::thread_rng();

    let alice = create_identity();
    let doc_a = GraphId::new();
    let doc_b = GraphId::new();
    let key = create_dummy_key();

    let lockbox_a = Lockbox::create(alice.public().encryption_key(), &key, &mut rng).unwrap();
    let lockbox_b = Lockbox::create(alice.public().encryption_key(), &key, &mut rng).unwrap();

    store
        .put_lockbox(doc_a, alice.public().signing_key(), &lockbox_a)
        .await
        .unwrap();
    store
        .put_lockbox(doc_b, alice.public().signing_key(), &lockbox_b)
        .await
        .unwrap();

    let retrieved = store
        .get_lockboxes_for_recipient(alice.public().signing_key())
        .await
        .unwrap();
    assert_eq!(retrieved.len(), 2);
}

#[test]
fn lockbox_tampered_associated_data_fails() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let bob = create_identity();
    let graph_key = create_dummy_key();

    let lockbox = Lockbox::create(bob.public().encryption_key(), &graph_key, &mut rng).unwrap();

    // Open with correct secret should work
    let result_ok = lockbox.open(bob.encryption_key());
    assert!(result_ok.is_ok());
    assert_eq!(result_ok.unwrap().as_bytes(), graph_key.as_bytes());

    // Create a different identity's secret
    let alice = create_identity();

    // Open with WRONG secret MUST fail (AD mismatch - different recipient)
    let result_wrong = lockbox.open(alice.encryption_key());
    assert!(
        result_wrong.is_err(),
        "Lockbox must fail when opened with wrong recipient's secret (AD mismatch)"
    );
}
