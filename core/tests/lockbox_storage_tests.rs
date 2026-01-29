use rand::rngs::OsRng;
use sovereign_core::crypto::{GraphKey, Lockbox};
use sovereign_core::graph::GraphId;
use sovereign_core::identity::SecretIdentity;
use sovereign_core::store::{GraphStore, InMemoryStore};

#[test]
fn store_can_save_and_load_lockboxes() {
    let mut rng = OsRng;
    let _sender = SecretIdentity::generate(&mut rng);
    let recipient = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let graph_key = GraphKey::generate(&mut rng);

    let lockbox = Lockbox::create(recipient.public().encryption_key(), &graph_key, &mut rng)
        .expect("Create failed");

    let mut store = InMemoryStore::new();

    store
        .put_lockbox(graph_id, recipient.public().encryption_key(), &lockbox)
        .unwrap();

    let results = store
        .get_lockboxes_for_recipient(recipient.public().encryption_key())
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, graph_id);
    assert_eq!(
        results[0].1.ephemeral_public_key,
        lockbox.ephemeral_public_key
    );
}

#[test]
fn store_returns_empty_for_unknown_recipient() {
    let mut rng = OsRng;
    let recipient = SecretIdentity::generate(&mut rng);
    let store = InMemoryStore::new();

    let results = store
        .get_lockboxes_for_recipient(recipient.public().encryption_key())
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn store_handles_multiple_lockboxes_for_same_recipient() {
    let mut rng = OsRng;
    let recipient = SecretIdentity::generate(&mut rng);
    let doc_a = GraphId::new();
    let doc_b = GraphId::new();
    let graph_key = GraphKey::generate(&mut rng);

    let lockbox_a =
        Lockbox::create(recipient.public().encryption_key(), &graph_key, &mut rng).unwrap();
    let lockbox_b =
        Lockbox::create(recipient.public().encryption_key(), &graph_key, &mut rng).unwrap();

    let mut store = InMemoryStore::new();

    store
        .put_lockbox(doc_a, recipient.public().encryption_key(), &lockbox_a)
        .unwrap();
    store
        .put_lockbox(doc_b, recipient.public().encryption_key(), &lockbox_b)
        .unwrap();

    let results = store
        .get_lockboxes_for_recipient(recipient.public().encryption_key())
        .unwrap();

    assert_eq!(results.len(), 2);
    // Order might be insertion order, but let's check existence
    assert!(
        results
            .iter()
            .any(|(id, lb)| *id == doc_a
                && lb.ephemeral_public_key == lockbox_a.ephemeral_public_key)
    );
    assert!(
        results
            .iter()
            .any(|(id, lb)| *id == doc_b
                && lb.ephemeral_public_key == lockbox_b.ephemeral_public_key)
    );
}

#[test]
fn store_isolates_recipients() {
    let mut rng = OsRng;
    let alice = SecretIdentity::generate(&mut rng);
    let bob = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let graph_key = GraphKey::generate(&mut rng);

    let lockbox_for_alice =
        Lockbox::create(alice.public().encryption_key(), &graph_key, &mut rng).unwrap();

    let mut store = InMemoryStore::new();
    store
        .put_lockbox(
            graph_id,
            alice.public().encryption_key(),
            &lockbox_for_alice,
        )
        .unwrap();

    // Bob checks his inbox
    let bob_results = store
        .get_lockboxes_for_recipient(bob.public().encryption_key())
        .unwrap();
    assert!(bob_results.is_empty());

    // Alice checks hers
    let alice_results = store
        .get_lockboxes_for_recipient(alice.public().encryption_key())
        .unwrap();
    assert_eq!(alice_results.len(), 1);
}
