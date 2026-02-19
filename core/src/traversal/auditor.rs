use crate::base::address::{Address, BlockId, ManifestId};
use crate::base::error::SovereignError;
use crate::graph::{Block, Manifest};
use crate::state::store::GraphStore;
use tracing::{Level, debug, span};

/// `Auditor` is the platform's Trust Gatekeeper.
///
/// It is responsible for verifying that every piece of data encountered
/// during traversal meets the mathematical and social laws of the Sovereign Web.
pub struct Auditor<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> Auditor<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Performs a full audit of a Manifest.
    ///
    /// 1. **Internal Integrity**: Verifies hash and signature.
    /// 2. **Social Authority**: (Future) Verifies signer is authorized in the Identity Graph.
    pub fn audit_manifest(&self, manifest: &Manifest) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "audit_manifest", id = ?manifest.id());
        let _enter = span.enter();

        // Tier 1: Mathematical Integrity
        manifest.verify_integrity()?;

        // Tier 2: Authority Check (Placeholder for full Identity Graph walk)
        debug!("Manifest integrity verified");
        Ok(())
    }

    /// Performs a full audit of a Block.
    ///
    /// 1. **Internal Integrity**: Verifies hash and signature.
    pub fn audit_block(&self, block: &Block) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "audit_block", id = ?block.id());
        let _enter = span.enter();

        // Tier 1: Mathematical Integrity
        block.verify_integrity()?;

        debug!("Block integrity verified");
        Ok(())
    }

    /// Verifies that an Address matches the expected type and exists in the store.
    pub fn verify_existence(&self, addr: &Address) -> Result<(), SovereignError> {
        if addr.codec() == crate::base::address::CODEC_SOVEREIGN_MANIFEST {
            let id = ManifestId::try_from(*addr)?;
            self.store.get_manifest(&id).and_then(|opt| {
                opt.ok_or_else(|| {
                    SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Manifest {}",
                        id
                    )))
                })
                .map(|_| ())
            })
        } else {
            let id = BlockId::try_from(*addr)?;
            self.store.get_block(&id).and_then(|opt| {
                opt.ok_or_else(|| {
                    SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Block {}",
                        id
                    )))
                })
                .map(|_| ())
            })
        }
    }
}
