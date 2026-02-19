use crate::base::address::{Address, ManifestId};
use crate::protocol::{Delta, Heads};

#[test]
fn heads_contains_graph_heads() {
    let graph_id = crate::GraphId::new();
    let head = ManifestId::from_sha256(&[1u8; 32]);
    let h = Heads::new(graph_id, vec![head]);

    assert_eq!(h.graph_id(), &graph_id);
    assert_eq!(h.heads().len(), 1);
}

#[test]
fn delta_contains_missing_addresses() {
    let m_id = ManifestId::from_sha256(&[1u8; 32]);
    let d = Delta::new(vec![Address::from(m_id)]);

    assert_eq!(d.missing().len(), 1);
    assert_eq!(d.missing()[0], Address::from(m_id));
}
