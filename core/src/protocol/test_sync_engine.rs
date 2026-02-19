use rand::rngs::OsRng;

use crate::{
    Address, BlockId, GraphId, ManifestId,
    graph::Manifest,
    identity::SecretIdentity,
    protocol::{Heads, Reconciler},
    state::{GraphStore, in_memory_store::InMemoryStore},
    traversal::{create_dummy_root, create_valid_anchor},
};

// Helper functions

pub fn create_identity() -> SecretIdentity {
    SecretIdentity::generate(&mut OsRng)
}

pub fn create_chain(
    length: usize,
    store: &mut InMemoryStore,
) -> (Vec<ManifestId>, crate::base::crypto::SigningPublicKey) {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let graph_id = GraphId::new();
    let root = create_dummy_root();

    let anchor = create_valid_anchor(store, &identity);

    let mut parents = vec![];
    let mut ids = vec![];

    for _ in 0..length {
        let manifest = Manifest::new(graph_id, root, parents.clone(), anchor, &identity);
        store.put_manifest(&manifest).unwrap();
        parents = vec![manifest.id()];
        ids.push(manifest.id());
    }
    (ids, identity.public().signing_key().clone())
}

#[test]
fn reconciler_identifies_peer_surplus() {
    let mut store = InMemoryStore::new();
    let (chain, master_key) = create_chain(3, &mut store); // A -> B -> C

    let graph_id = GraphId::new();

    // Scenario: PEER has the full chain [A, B, C]. SELF only has [A].
    let peer_heads = Heads::new(graph_id, vec![chain[2]]); // Peer is at C
    let self_heads = vec![chain[0]]; // Self is at A

    let reconciler = Reconciler::new(&store, master_key);
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .expect("Reconciliation failed");

    // I (Self) need B and C from the Peer.
    assert!(
        comparison
            .peer_surplus
            .missing()
            .contains(&Address::from(chain[1]))
    );
    assert!(
        comparison
            .peer_surplus
            .missing()
            .contains(&Address::from(chain[2]))
    );

    // Peer needs nothing from me (I have no surplus knowledge).
    assert!(comparison.self_surplus.is_empty());
}

#[test]
fn reconciler_identifies_self_surplus() {
    let mut store = InMemoryStore::new();
    let (chain, master_key) = create_chain(3, &mut store); // A -> B -> C

    let graph_id = GraphId::new();

    // Scenario: SELF has the full chain [A, B, C]. PEER only has [A].
    let peer_heads = Heads::new(graph_id, vec![chain[0]]); // Peer is at A
    let self_heads = vec![chain[2]]; // Self is at C

    let reconciler = Reconciler::new(&store, master_key);
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .expect("Reconciliation failed");

    // I (Self) need nothing from the Peer.
    assert!(comparison.peer_surplus.is_empty());

    // The Peer needs B and C from me.
    assert!(
        comparison
            .self_surplus
            .missing()
            .contains(&Address::from(chain[1]))
    );
    assert!(
        comparison
            .self_surplus
            .missing()
            .contains(&Address::from(chain[2]))
    );
}

#[test]
fn reconciler_handles_symmetric_forks() {
    let mut store = InMemoryStore::new();
    let (chain, master_key) = create_chain(1, &mut store); // A
    let m_a_id = chain[0];

    let identity = create_identity();
    let graph_id = GraphId::new();
    let anchor = create_valid_anchor(&mut store, &identity);

    // Create two DIFFERENT content roots to force different CIDs
    let root_b = BlockId::from_sha256(&[0xB1; 32]);
    let root_c = BlockId::from_sha256(&[0xC1; 32]);

    // 2. Branch B (Child of A)
    let m_b = Manifest::new(graph_id, root_b, vec![m_a_id], anchor, &identity);
    store.put_manifest(&m_b).unwrap();

    // 3. Branch C (Child of A)
    let m_c = Manifest::new(graph_id, root_c, vec![m_a_id], anchor, &identity);
    store.put_manifest(&m_c).unwrap();

    // Scenario: SELF has Branch [C]. PEER has Branch [B].
    let self_heads = vec![m_c.id()];
    let peer_heads = Heads::new(graph_id, vec![m_b.id()]);

    let reconciler = Reconciler::new(&store, master_key);
    let comparison = reconciler.reconcile(&peer_heads, &self_heads).unwrap();

    // I need B from you.
    assert!(
        comparison
            .peer_surplus
            .missing()
            .contains(&Address::from(m_b.id()))
    );
    // You need C from me.
    assert!(
        comparison
            .self_surplus
            .missing()
            .contains(&Address::from(m_c.id()))
    );
}

#[test]
fn reconciler_returns_empty_if_identical() {
    let mut store = InMemoryStore::new();
    let (chain, master_key) = create_chain(2, &mut store); // A -> B
    let self_heads = vec![chain[1]]; // B
    let graph_id = GraphId::new();
    let peer_heads = Heads::new(graph_id, vec![chain[1]]); // B

    let reconciler = Reconciler::new(&store, master_key);
    let comparison = reconciler.reconcile(&peer_heads, &self_heads).unwrap();

    assert!(comparison.peer_surplus.is_empty());
    assert!(comparison.self_surplus.is_empty());
}
