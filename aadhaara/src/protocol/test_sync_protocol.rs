use crate::base::address::{Address, ManifestId};
use crate::protocol::{Comparison, ConvergenceReport, Delta, Heads, Portion};

#[test]
fn heads_contains_graph_heads() {
    let graph_id = crate::GraphId::new();
    let head = ManifestId::from_sha256(&[1u8; 32]);
    let h = Heads::new(graph_id, vec![head]);

    assert_eq!(h.graph_id(), &graph_id);
    assert_eq!(h.heads().len(), 1);
}

#[test]
fn heads_with_multiple_heads() {
    let graph_id = crate::GraphId::new();
    let head1 = ManifestId::from_sha256(&[1u8; 32]);
    let head2 = ManifestId::from_sha256(&[2u8; 32]);
    let h = Heads::new(graph_id, vec![head1, head2]);

    assert_eq!(h.heads().len(), 2);
    assert_eq!(h.heads(), &[head1, head2]);
}

#[test]
fn delta_contains_missing_addresses() {
    let m_id = ManifestId::from_sha256(&[1u8; 32]);
    let d = Delta::new(vec![Address::from(m_id)]);

    assert_eq!(d.missing().len(), 1);
    assert_eq!(d.missing()[0], Address::from(m_id));
}

#[test]
fn delta_empty_check() {
    let d = Delta::new(vec![]);
    assert!(d.is_empty());
}

#[test]
fn comparison_has_both_surpluses() {
    let peer_addr = Address::from(crate::BlockId::from_sha256(&[1u8; 32]));
    let self_addr = Address::from(crate::BlockId::from_sha256(&[2u8; 32]));

    let comparison = Comparison {
        peer_surplus: Delta::new(vec![peer_addr]),
        self_surplus: Delta::new(vec![self_addr]),
    };

    assert!(!comparison.peer_surplus.is_empty());
    assert!(!comparison.self_surplus.is_empty());
}

#[test]
fn convergence_report_tracks_sync_stats() {
    let report = ConvergenceReport {
        manifests_synced: 5,
        blocks_synced: 10,
        total_bytes: 1024,
    };

    assert_eq!(report.manifests_synced, 5);
    assert_eq!(report.blocks_synced, 10);
    assert_eq!(report.total_bytes, 1024);
}

#[test]
fn portion_carries_id_and_data() {
    let id = Address::from(crate::BlockId::from_sha256(&[1u8; 32]));
    let data = b"test data".to_vec();

    let portion = Portion::new(id, data.clone());

    assert_eq!(portion.id(), &id);
    assert_eq!(portion.data(), &data);
}
