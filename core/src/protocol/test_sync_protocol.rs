use crate::{
    BlockId, GraphId, ManifestId,
    protocol::{SyncRequest, SyncResponse},
};

#[test]
fn sync_request_contains_graph_heads() {
    let head1 = ManifestId::from_sha256(&[1u8; 32]);
    let head2 = ManifestId::from_sha256(&[2u8; 32]);
    let graph_id = GraphId::new();

    let request = SyncRequest::new(graph_id, vec![head1, head2]);

    assert_eq!(request.heads().len(), 2);
    assert!(request.heads().contains(&head1));
    assert!(request.heads().contains(&head2));
}

#[test]
fn sync_response_contains_missing_ids() {
    let m1 = ManifestId::from_sha256(&[0xA1; 32]);
    let b1 = BlockId::from_sha256(&[0xB1; 32]);

    let response = SyncResponse::new(vec![m1], vec![b1]);

    assert_eq!(response.missing_manifests().len(), 1);
    assert_eq!(response.missing_blocks().len(), 1);
    assert_eq!(response.missing_manifests()[0], m1);
    assert_eq!(response.missing_blocks()[0], b1);
}
