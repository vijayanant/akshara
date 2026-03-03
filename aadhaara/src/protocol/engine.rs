use crate::base::address::{Address, BlockId, ManifestId};
use crate::base::crypto::SigningPublicKey;
use crate::base::error::{ProtocolError, SovereignError};
use crate::protocol::{Comparison, ConvergenceReport, Delta, Heads, Portion};
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use metrics::counter;
use std::collections::{HashSet, VecDeque};
use tracing::{Level, debug, span};

/// `Reconciler` implements the pure mathematical logic of graph convergence.
pub struct Reconciler<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
    /// The immutable Master Public Key that serves as the root of trust for this reconciliation.
    pub(crate) expected_root_key: SigningPublicKey,
}

impl<'a, S: GraphStore + ?Sized> Reconciler<'a, S> {
    /// Creates a new Reconciler bound to a specific root of trust.
    pub fn new(store: &'a S, expected_root_key: SigningPublicKey) -> Self {
        Self {
            store,
            expected_root_key,
        }
    }

    /// Determines the bi-directional knowledge gap between two frontiers.
    pub async fn reconcile(
        &self,
        peer_heads: &Heads,
        local_heads: &[ManifestId],
    ) -> Result<Comparison, SovereignError> {
        let span = span!(Level::INFO, "reconcile", graph_id = ?peer_heads.graph_id);
        let _enter = span.enter();

        // 1. Hardening: Bound check inputs
        if peer_heads.heads().len() > 1024 || local_heads.len() > 1024 {
            return Err(SovereignError::Protocol(ProtocolError::TooManyHeads(1024)));
        }

        let walker = GraphWalker::new(self.store, self.expected_root_key.clone());

        // 2. Calculate Local Known Set (My full manifest reality)
        let mut self_known = HashSet::new();
        for head in local_heads {
            self_known.insert(*head);
            self_known.extend(walker.get_ancestors(head).await?);
        }

        // 3. Calculate Peer Known Set (Peer's full manifest reality)
        let mut peer_known = HashSet::new();
        for head in peer_heads.heads() {
            peer_known.insert(*head);
            peer_known.extend(walker.get_ancestors(head).await?);
        }

        // 4. Calculate Bi-directional differences
        let peer_surplus_manifests: Vec<ManifestId> =
            peer_known.difference(&self_known).cloned().collect();
        let self_surplus_manifests: Vec<ManifestId> =
            self_known.difference(&peer_known).cloned().collect();

        // 5. Expand manifests to full address deltas (including recursive content)
        let peer_surplus_delta = self.expand_to_delta(&peer_surplus_manifests).await?;
        let self_surplus_delta = self.expand_to_delta(&self_surplus_manifests).await?;

        debug!(
            peer_surplus = peer_surplus_delta.missing().len(),
            self_surplus = self_surplus_delta.missing().len(),
            "Symmetric reconciliation complete"
        );

        // Hardening: Bound check result
        if peer_surplus_delta.missing().len() > 100_000
            || self_surplus_delta.missing().len() > 100_000
        {
            return Err(SovereignError::Protocol(ProtocolError::DeltaTooLarge(
                100_000,
            )));
        }

        counter!("sovereign.protocol.reconcile.peer_surplus")
            .increment(peer_surplus_delta.missing().len() as u64);
        counter!("sovereign.protocol.reconcile.self_surplus")
            .increment(self_surplus_delta.missing().len() as u64);

        Ok(Comparison {
            peer_surplus: peer_surplus_delta,
            self_surplus: self_surplus_delta,
        })
    }

    /// Recursively identifies every missing Address (Manifests + Merkle Tree of Blocks).
    fn expand_to_delta<'b>(
        &'b self,
        manifest_ids: &'b [ManifestId],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Delta, SovereignError>> + Send + 'b>,
    > {
        Box::pin(async move {
            let mut addresses = HashSet::new();
            let mut block_queue = VecDeque::new();

            for m_id in manifest_ids {
                addresses.insert(Address::from(*m_id));
                if let Some(manifest) = self.store.get_manifest(m_id).await? {
                    let root_id = manifest.content_root();
                    if addresses.insert(Address::from(root_id)) {
                        block_queue.push_back(root_id);
                    }
                }
            }

            // Perform a BFS walk of the Merkle Index Tree to find all associated blocks
            while let Some(current_block_id) = block_queue.pop_front() {
                if let Some(block) = self.store.get_block(&current_block_id).await? {
                    // If it's an index block, we need to find its children
                    if block.block_type() == "index" {
                        // Note: In the blind model, the Relay CANNOT recursively expand.
                    }

                    // Add parents (for linear block history if applicable)
                    for parent in block.parents() {
                        if addresses.insert(Address::from(*parent)) {
                            block_queue.push_back(*parent);
                        }
                    }
                }
            }

            Ok(Delta::new(addresses.into_iter().collect()))
        })
    }

    /// Fulfills a `Delta` by yielding an iterator of raw `Portion` units.
    pub async fn fulfill(&self, delta: &Delta) -> Result<Vec<Portion>, SovereignError> {
        let mut portions = Vec::new();
        for addr in delta.missing() {
            if addr.codec() == crate::base::address::CODEC_AKSHARA_MANIFEST {
                let id = ManifestId::try_from(*addr)?;
                let manifest = self.store.get_manifest(&id).await?.ok_or_else(|| {
                    SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Manifest {}",
                        id
                    )))
                })?;
                let data = crate::base::encoding::to_canonical_bytes(&manifest)?;
                portions.push(Portion::new(*addr, data));
            } else {
                let id = BlockId::try_from(*addr)?;
                let block = self.store.get_block(&id).await?.ok_or_else(|| {
                    SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Block {}",
                        id
                    )))
                })?;
                let data = crate::base::encoding::to_canonical_bytes(&block)?;
                portions.push(Portion::new(*addr, data));
            }
        }
        Ok(portions)
    }

    /// High-level utility to ingest data from a peer into a local store.
    ///
    /// This method simplifies the synchronization turn by automatically
    /// fulfilling a delta and storing the resulting portions.
    pub async fn converge<Dest: GraphStore + ?Sized>(
        &self,
        delta: &Delta,
        dest: &mut Dest,
    ) -> Result<ConvergenceReport, SovereignError> {
        let mut report = ConvergenceReport::default();

        for portion in self.fulfill(delta).await? {
            let addr = portion.id();
            let data = portion.data();

            report.total_bytes += data.len();

            if addr.codec() == crate::base::address::CODEC_AKSHARA_MANIFEST {
                let m: crate::graph::Manifest = crate::base::encoding::from_canonical_bytes(data)?;
                dest.put_manifest(&m).await?;
                report.manifests_synced += 1;
            } else {
                let b: crate::graph::Block = crate::base::encoding::from_canonical_bytes(data)?;
                dest.put_block(&b).await?;
                report.blocks_synced += 1;
            }
        }

        debug!(
            manifests = report.manifests_synced,
            blocks = report.blocks_synced,
            bytes = report.total_bytes,
            "Convergence turn complete"
        );

        Ok(report)
    }
}
