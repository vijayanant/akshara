use crate::base::address::{Address, BlockId, ManifestId};
use crate::base::crypto::SigningPublicKey;
use crate::base::error::AksharaError;
use crate::graph::{Block, Manifest};
use crate::identity::IdentityGraph;
use crate::state::store::GraphStore;
use sha2::Digest;
use tracing::{Level, debug, span};

/// `Auditor` is the platform's Trust Gatekeeper.
///
/// It verifies that every piece of data encountered during traversal
/// meets the mathematical and social laws of the Sovereign Web.
///
/// # Self-Sovereign Authority Verification
///
/// The Auditor does NOT require an external root key. Instead, it discovers
/// the root of trust from the identity graph pointed to by each manifest's
/// `identity_anchor`. The genesis of the identity graph (signed by the
/// Legislator branch) is the root of trust. All manifest signers must trace
/// their authority back through the identity graph to that genesis.
pub struct Auditor<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
    pub(crate) latest_identity: Option<ManifestId>,
}

impl<'a, S: GraphStore + ?Sized> Auditor<'a, S> {
    /// Creates a new Auditor.
    ///
    /// The Auditor discovers the root of trust from the identity graph
    /// itself — no external key is required or accepted.
    pub fn new(store: &'a S) -> Self {
        Self {
            store,
            latest_identity: None,
        }
    }

    pub fn with_latest_identity(mut self, identity: ManifestId) -> Self {
        self.latest_identity = Some(identity);
        self
    }

    /// Discovers the Legislator root key from the manifest's identity graph.
    ///
    /// For genesis manifests (`identity_anchor == null`), the author IS the root.
    /// For all other manifests, this walks the identity graph manifest chain
    /// back to its genesis.
    async fn discover_root_key(
        &self,
        manifest: &Manifest,
    ) -> Result<SigningPublicKey, AksharaError> {
        // Genesis manifest: the author IS the root of trust
        if manifest.identity_anchor() == ManifestId::null() {
            return Ok(manifest.author().clone());
        }
        // Non-genesis: walk the identity graph to find the genesis
        self.discover_identity_root(&manifest.identity_anchor())
            .await
    }

    /// Walks the identity graph manifest chain to find the genesis.
    async fn discover_identity_root(
        &self,
        anchor: &ManifestId,
    ) -> Result<SigningPublicKey, AksharaError> {
        let anchor_manifest = self.store.get_manifest(anchor).await?.ok_or_else(|| {
            AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                "Identity anchor {}",
                anchor
            )))
        })?;

        // If this is the genesis of the identity graph, its author is the root.
        if anchor_manifest.identity_anchor() == ManifestId::null() {
            return Ok(anchor_manifest.author().clone());
        }

        // Otherwise walk back through the identity graph's parents.
        for parent_id in anchor_manifest.parents() {
            if let Ok(root_key) = Box::pin(self.discover_identity_root(parent_id)).await {
                return Ok(root_key);
            }
        }

        Err(AksharaError::Integrity(
            crate::base::error::IntegrityError::UnauthorizedSigner(
                "Could not find genesis manifest in the identity graph".to_string(),
            ),
        ))
    }

    pub async fn audit_manifest(&self, manifest: &Manifest) -> Result<(), AksharaError> {
        let span = span!(Level::DEBUG, "audit_manifest", id = ?manifest.id());
        let _enter = span.enter();

        manifest.verify_integrity()?;

        // Genesis manifests MUST be signed by a Legislator (m/0')
        if manifest.identity_anchor() == ManifestId::null() {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"m/44'/999'/0'/0'/0'");
            let legislator_hash: [u8; 32] = hasher.finalize().into();

            if manifest.signer_path_hash() != &legislator_hash {
                return Err(crate::base::error::AksharaError::Integrity(
                    crate::base::error::IntegrityError::UnauthorizedSigner(
                        "Administrative action requires Legislator branch (m/0') hash, but found mismatch".to_string()
                    ),
                ));
            }
        }

        let root_key = self.discover_root_key(manifest).await?;

        let identity_graph = IdentityGraph::new(self.store);
        identity_graph
            .verify_authority(
                manifest.author(),
                &manifest.identity_anchor(),
                &root_key,
                self.latest_identity.as_ref(),
            )
            .await?;

        debug!("Manifest fully audited (Integrity + Authority)");
        Ok(())
    }

    pub fn audit_block(&self, block: &Block) -> Result<(), AksharaError> {
        let span = span!(Level::DEBUG, "audit_block", id = ?block.id());
        let _enter = span.enter();
        block.verify_integrity()?;
        debug!("Block integrity verified");
        Ok(())
    }

    pub async fn verify_existence(&self, addr: &Address) -> Result<(), AksharaError> {
        if addr.codec() == crate::base::address::CODEC_AKSHARA_MANIFEST {
            let id = ManifestId::try_from(*addr)?;
            self.store.get_manifest(&id).await.and_then(|opt| {
                opt.ok_or_else(|| {
                    AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
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
                    AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Block {}",
                        id
                    )))
                })
                .map(|_| ())
            })
        }
    }
}
