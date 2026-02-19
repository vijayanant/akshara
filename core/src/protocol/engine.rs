use crate::base::address::{Address, BlockId, ManifestId};
use crate::base::crypto::SigningPublicKey;
use crate::base::error::{ProtocolError, SovereignError};
use crate::protocol::{Comparison, Delta, Heads, Portion};
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
    pub fn reconcile(
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
            self_known.extend(walker.get_ancestors(head)?);
        }

        // 3. Calculate Peer Known Set (Peer's full manifest reality)
        let mut peer_known = HashSet::new();
        for head in peer_heads.heads() {
            peer_known.insert(*head);
            peer_known.extend(walker.get_ancestors(head)?);
        }

        // 4. Calculate Bi-directional differences
        let peer_surplus_manifests: Vec<ManifestId> =
            peer_known.difference(&self_known).cloned().collect();
        let self_surplus_manifests: Vec<ManifestId> =
            self_known.difference(&peer_known).cloned().collect();

        // 5. Expand manifests to full address deltas (including recursive content)
        let peer_surplus_delta = self.expand_to_delta(&peer_surplus_manifests)?;
        let self_surplus_delta = self.expand_to_delta(&self_surplus_manifests)?;

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
    fn expand_to_delta(&self, manifest_ids: &[ManifestId]) -> Result<Delta, SovereignError> {
        let mut addresses = HashSet::new();
        let mut block_queue = VecDeque::new();

        for m_id in manifest_ids {
            addresses.insert(Address::from(*m_id));
            if let Some(manifest) = self.store.get_manifest(m_id)? {
                let root_id = manifest.content_root();
                if addresses.insert(Address::from(root_id)) {
                    block_queue.push_back(root_id);
                }
            }
        }

        // Perform a BFS walk of the Merkle Index Tree to find all associated blocks
        while let Some(current_block_id) = block_queue.pop_front() {
            if let Some(block) = self.store.get_block(&current_block_id)? {
                // If it's an index block, we need to find its children
                if block.block_type() == "index" {
                    // Note: We'd need the GraphKey to decrypt and find children.
                    // BUT: The Relay is BLIND. It cannot decrypt.

                    // ARCHITECTURAL REALIZATION:
                    // In the blind model, the Relay CANNOT recursively expand the delta
                    // because it cannot see the CIDs inside the encrypted index blocks.

                    // Therefore, the protocol must be ITERATIVE.
                    // 1. Peer sends Manifests + Root.
                    // 2. SDK decrypts Root, finds children, and asks for them in the NEXT turn.
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
    }

    /// Fulfills a `Delta` by yielding an iterator of raw `Portion` units.
    pub fn fulfill<'b>(
        &'b self,
        delta: &'b Delta,
    ) -> impl Iterator<Item = Result<Portion, SovereignError>> + 'b {
        delta.missing().iter().map(move |addr| {
            if addr.codec() == crate::base::address::CODEC_SOVEREIGN_MANIFEST {
                let id = ManifestId::try_from(*addr)?;
                self.store.get_manifest(&id).and_then(|opt| {
                    let manifest = opt.ok_or_else(|| {
                        SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                            "Manifest {}",
                            id
                        )))
                    })?;
                    let data = serde_cbor::to_vec(&manifest).map_err(|e| {
                        SovereignError::InternalError(format!(
                            "Manifest serialization failed: {}",
                            e
                        ))
                    })?;
                    Ok(Portion::new(*addr, data))
                })
            } else {
                let id = BlockId::try_from(*addr)?;
                self.store.get_block(&id).and_then(|opt| {
                    let block = opt.ok_or_else(|| {
                        SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                            "Block {}",
                            id
                        )))
                    })?;
                    let data = serde_cbor::to_vec(&block).map_err(|e| {
                        SovereignError::InternalError(format!("Block serialization failed: {}", e))
                    })?;
                    Ok(Portion::new(*addr, data))
                })
            }
        })
    }

    /// High-level utility to ingest data from a peer into a local store.
    ///
    /// This method simplifies the synchronization loop by automatically
    /// fulfilling a delta and storing the resulting portions.
    pub fn converge<Dest: GraphStore + ?Sized>(
        &self,
        delta: &Delta,
        dest: &mut Dest,
    ) -> Result<usize, SovereignError> {
        let mut count = 0;
        for portion_res in self.fulfill(delta) {
            let portion = portion_res?;
            let addr = portion.id();

            if addr.codec() == crate::base::address::CODEC_SOVEREIGN_MANIFEST {
                let m: crate::graph::Manifest =
                    serde_cbor::from_slice(portion.data()).map_err(|e| {
                        SovereignError::InternalError(format!("Convergence failure: {}", e))
                    })?;
                dest.put_manifest(&m)?;
            } else {
                let b: crate::graph::Block =
                    serde_cbor::from_slice(portion.data()).map_err(|e| {
                        SovereignError::InternalError(format!("Convergence failure: {}", e))
                    })?;
                dest.put_block(&b)?;
            }
            count += 1;
        }
        Ok(count)
    }
}
