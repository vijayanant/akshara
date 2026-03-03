use crate::base::address::{Address, BlockId, ManifestId};
use crate::base::crypto::SigningPublicKey;
use crate::base::error::SovereignError;
use crate::graph::{Block, Manifest};
use crate::identity::IdentityGraph;
use crate::state::store::GraphStore;
use tracing::{Level, debug, span};

/// `Auditor` is the platform's Trust Gatekeeper.
///
/// It is responsible for verifying that every piece of data encountered
/// during traversal meets the mathematical and social laws of the Sovereign Web.
pub struct Auditor<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
    /// The immutable Master Public Key that serves as the root of trust for this audit.
    pub(crate) expected_root_key: SigningPublicKey,
}

impl<'a, S: GraphStore + ?Sized> Auditor<'a, S> {
    /// Creates a new Auditor bound to a specific Master Root Key.
    pub fn new(store: &'a S, expected_root_key: SigningPublicKey) -> Self {
        Self {
            store,
            expected_root_key,
        }
    }

    /// Performs a full audit of a Manifest, including mathematical and social integrity.
    pub async fn audit_manifest(&self, manifest: &Manifest) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "audit_manifest", id = ?manifest.id());
        let _enter = span.enter();

        // Tier 1: Mathematical Integrity (Hash & Signature)
        manifest.verify_integrity()?;

        // Tier 2: Path-Aware Purpose Enforcement
        // Genesis manifests (administrative) MUST be signed by a Legislator (m/0')
        if manifest.identity_anchor() == ManifestId::null()
            && !crate::identity::paths::is_legislator_path(manifest.signer_path())
        {
            return Err(crate::base::error::SovereignError::Integrity(
                crate::base::error::IntegrityError::UnauthorizedSigner(format!(
                    "Administrative action requires Legislator branch, but signed by {}",
                    manifest.signer_path()
                )),
            ));
        }

        // Tier 3: Social Authority (Causality)
        let identity_graph = IdentityGraph::new(self.store);

        // Proving the Right to Rule:
        // Is this signer's public key present and unrevoked in the graph
        // that ultimately anchors to our expected_root_key?
        identity_graph
            .verify_authority(
                manifest.author(),
                &manifest.identity_anchor(),
                &self.expected_root_key,
            )
            .await?;

        debug!("Manifest fully audited (Integrity + Authority)");
        Ok(())
    }

    /// Performs a full audit of a Block.
    pub fn audit_block(&self, block: &Block) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "audit_block", id = ?block.id());
        let _enter = span.enter();

        // Tier 1: Mathematical Integrity
        block.verify_integrity()?;

        debug!("Block integrity verified");
        Ok(())
    }

    /// Verifies that an Address matches the expected type and exists in the store.
    pub async fn verify_existence(&self, addr: &Address) -> Result<(), SovereignError> {
        if addr.codec() == crate::base::address::CODEC_AKSHARA_MANIFEST {
            let id = ManifestId::try_from(*addr)?;
            self.store.get_manifest(&id).await.and_then(|opt| {
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
            self.store.get_block(&id).await.and_then(|opt| {
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
