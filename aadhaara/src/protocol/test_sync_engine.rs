use crate::{
    Address, BlockId, ManifestId,
    protocol::{Heads, Reconciler},
    state::in_memory_store::InMemoryStore,
    test_utils::TestFactory,
};

#[tokio::test]
async fn reconciler_handles_empty_heads() {
    let factory = TestFactory::with_anchor().await;
    let manifest = factory.create_genesis().await;

    let reconciler = Reconciler::new(factory.store.as_ref());

    // Both peers have empty heads - should reconcile to empty delta
    let peer_heads = Heads::new(factory.graph_id, vec![]);
    let self_heads: Vec<ManifestId> = vec![];

    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .unwrap();

    assert!(comparison.peer_surplus.is_empty());
    assert!(comparison.self_surplus.is_empty());
    // Use manifest to avoid unused warning
    assert_ne!(manifest.id(), ManifestId::null());
}

#[tokio::test]
async fn reconciler_handles_one_empty_one_with_heads() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;
    let m3 = factory
        .create_manifest(factory.dummy_root(), vec![m2.id()])
        .await;

    let reconciler = Reconciler::new(factory.store.as_ref());

    // Peer has heads, self is empty
    let peer_heads = Heads::new(factory.graph_id, vec![m3.id()]);
    let self_heads: Vec<ManifestId> = vec![];

    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .unwrap();

    assert!(!comparison.peer_surplus.is_empty());
    assert!(comparison.self_surplus.is_empty());
}

#[tokio::test]
async fn reconciler_rejects_too_many_heads() {
    let factory = TestFactory::with_anchor().await;

    // Create 1025 heads (exceeds limit of 1024)
    let mut heads = vec![];
    for _i in 0..1025 {
        let manifest = factory.create_genesis().await;
        heads.push(manifest.id());
    }

    let reconciler = Reconciler::new(factory.store.as_ref());
    let peer_heads = Heads::new(factory.graph_id, heads);
    let self_heads: Vec<ManifestId> = vec![];

    let result = reconciler.reconcile(&peer_heads, &self_heads).await;

    assert!(result.is_err(), "Should reject too many heads");
}

#[tokio::test]
async fn reconciler_identifies_peer_surplus() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;
    let m3 = factory
        .create_manifest(factory.dummy_root(), vec![m2.id()])
        .await;

    // Scenario: PEER has the full chain [M1, M2, M3]. SELF only has [M1].
    let peer_heads = Heads::new(factory.graph_id, vec![m3.id()]); // Peer is at M3
    let self_heads = vec![m1.id()]; // Self is at M1

    let reconciler = Reconciler::new(factory.store.as_ref());
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .expect("Reconciliation failed");

    // I (Self) need M2 and M3 from the Peer.
    assert!(
        comparison
            .peer_surplus
            .missing()
            .contains(&Address::from(m2.id()))
    );
    assert!(
        comparison
            .peer_surplus
            .missing()
            .contains(&Address::from(m3.id()))
    );

    // Peer needs nothing from me (I have no surplus knowledge).
    assert!(comparison.self_surplus.is_empty());
}

#[tokio::test]
async fn reconciler_identifies_self_surplus() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;
    let m3 = factory
        .create_manifest(factory.dummy_root(), vec![m2.id()])
        .await;

    // Scenario: SELF has the full chain [M1, M2, M3]. PEER only has [M1].
    let peer_heads = Heads::new(factory.graph_id, vec![m1.id()]); // Peer is at M1
    let self_heads = vec![m3.id()]; // Self is at M3

    let reconciler = Reconciler::new(factory.store.as_ref());
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .expect("Reconciliation failed");

    // I (Self) need nothing from the Peer.
    assert!(comparison.peer_surplus.is_empty());

    // The Peer needs M2 and M3 from me.
    assert!(
        comparison
            .self_surplus
            .missing()
            .contains(&Address::from(m2.id()))
    );
    assert!(
        comparison
            .self_surplus
            .missing()
            .contains(&Address::from(m3.id()))
    );
}

#[tokio::test]
async fn reconciler_handles_symmetric_forks() {
    let factory = TestFactory::with_anchor().await;
    let m_a = factory.create_genesis().await;

    // Create two DIFFERENT content roots to force different CIDs
    let root_b = BlockId::from_sha256(&[0xB1; 32]);
    let root_c = BlockId::from_sha256(&[0xC1; 32]);

    // 2. Branch B (Child of A)
    let m_b = factory.create_manifest(root_b, vec![m_a.id()]).await;

    // 3. Branch C (Child of A)
    let m_c = factory.create_manifest(root_c, vec![m_a.id()]).await;

    // Scenario: SELF has Branch [C]. PEER has Branch [B].
    let self_heads = vec![m_c.id()];
    let peer_heads = Heads::new(factory.graph_id, vec![m_b.id()]);

    let reconciler = Reconciler::new(factory.store.as_ref());
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .unwrap();

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

#[tokio::test]
async fn reconciler_returns_empty_if_identical() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;

    let self_heads = vec![m2.id()]; // M2
    let peer_heads = Heads::new(factory.graph_id, vec![m2.id()]); // M2

    let reconciler = Reconciler::new(factory.store.as_ref());
    let comparison = reconciler
        .reconcile(&peer_heads, &self_heads)
        .await
        .unwrap();

    assert!(comparison.peer_surplus.is_empty());
    assert!(comparison.self_surplus.is_empty());
}

#[tokio::test]
async fn test_converge_returns_detailed_report() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;

    // We create a second store to converge INTO
    let dest_store = InMemoryStore::new();
    let reconciler = Reconciler::new(factory.store.as_ref());

    // We create a delta for the entire chain
    let delta = crate::protocol::Delta::new(vec![Address::from(m1.id()), Address::from(m2.id())]);

    let report = reconciler
        .converge(&delta, &dest_store)
        .await
        .expect("Convergence failed");

    // TDD Assertions: We expect a struct with telemetry
    assert_eq!(report.manifests_synced, 2);
    assert_eq!(report.blocks_synced, 0); // Manifests only in this delta
    assert!(report.total_bytes > 0);
}

#[tokio::test]
async fn test_converge_empty_delta() {
    let factory = TestFactory::new().await;
    let reconciler = Reconciler::new(factory.store.as_ref());

    let delta = crate::protocol::Delta::default();
    let report = reconciler
        .converge(&delta, &InMemoryStore::new())
        .await
        .unwrap();

    assert_eq!(report.manifests_synced, 0);
    assert_eq!(report.blocks_synced, 0);
    assert_eq!(report.total_bytes, 0);
}

#[tokio::test]
async fn test_converge_idempotency_with_duplicates() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;

    let dest_store = InMemoryStore::new();
    let reconciler = Reconciler::new(factory.store.as_ref());

    // Delta contains the SAME manifest twice
    let delta = crate::protocol::Delta::new(vec![Address::from(m1.id()), Address::from(m1.id())]);

    let report = reconciler.converge(&delta, &dest_store).await.unwrap();

    // Telemetry reflects the work done: 2 items processed (even if redundant at storage layer)
    assert_eq!(report.manifests_synced, 2);
}

#[tokio::test]
async fn test_converge_fails_on_first_error() {
    let factory = TestFactory::with_anchor().await;
    let m1 = factory.create_genesis().await;
    let m2 = factory
        .create_manifest(factory.dummy_root(), vec![m1.id()])
        .await;

    let dest_store = InMemoryStore::new();
    let reconciler = Reconciler::new(factory.store.as_ref());

    // We add a non-existent address to the middle of the delta
    let delta = crate::protocol::Delta::new(vec![
        Address::from(m1.id()),
        Address::from(BlockId::from_sha256(&[0xEE; 32])), // Unknown block
        Address::from(m2.id()),
    ]);

    let result = reconciler.converge(&delta, &dest_store).await;

    // Must return an error, and the process stops
    assert!(result.is_err());
}
