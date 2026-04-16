use crate::base::address::{Address, BlockId, GraphId, ManifestId};
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
    /// Memoized root key discovered during this session to avoid O(N^2) walks.
    pub(crate) memoized_root_key: std::sync::Arc<std::sync::RwLock<Option<SigningPublicKey>>>,
}

impl<'a, S: GraphStore + ?Sized> Auditor<'a, S> {
    /// Creates a new Auditor.
    pub fn new(store: &'a S) -> Self {
        Self {
            store,
            latest_identity: None,
            memoized_root_key: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub fn with_latest_identity(mut self, identity: ManifestId) -> Self {
        self.latest_identity = Some(identity);
        self
    }

    /// Discovers the Legislator root key from the manifest's identity graph.
    async fn discover_root_key(
        &self,
        manifest: &Manifest,
    ) -> Result<SigningPublicKey, AksharaError> {
        // 1. Check memoization first
        {
            let cache = self.memoized_root_key.read().map_err(|_| {
                AksharaError::InternalError("memoized_root_key lock poisoned".to_string())
            })?;
            if let Some(ref key) = *cache {
                return Ok(key.clone());
            }
        }

        // 2. Not in cache, perform discovery
        let root_key = if manifest.identity_anchor() == ManifestId::null() {
            // Genesis manifest: the author IS the root of trust
            manifest.author().clone()
        } else {
            // Non-genesis: walk the identity graph to find the genesis
            self.discover_identity_root_iterative(&manifest.identity_anchor())
                .await?
        };

        // 3. Update cache
        {
            let mut cache = self.memoized_root_key.write().map_err(|_| {
                AksharaError::InternalError("memoized_root_key lock poisoned".to_string())
            })?;
            *cache = Some(root_key.clone());
        }

        Ok(root_key)
    }

    /// Iterative discovery of the identity root with depth limits and convergence checks.
    async fn discover_identity_root_iterative(
        &self,
        anchor: &ManifestId,
    ) -> Result<SigningPublicKey, AksharaError> {
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(*anchor);

        let mut discovered_root: Option<SigningPublicKey> = None;
        let mut visited = std::collections::HashSet::new();
        let mut depth = 0;
        const MAX_IDENTITY_DEPTH: usize = 1024;

        while let Some(current_id) = queue.pop_front() {
            if !visited.insert(current_id) {
                continue;
            }

            depth += 1;
            if depth > MAX_IDENTITY_DEPTH {
                return Err(AksharaError::Integrity(
                    crate::base::error::IntegrityError::UnauthorizedSigner(
                        "Identity graph depth limit exceeded".to_string(),
                    ),
                ));
            }

            let manifest = self.store.get_manifest(&current_id).await?.ok_or_else(|| {
                AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                    "Identity anchor {}",
                    current_id
                )))
            })?;

            if manifest.identity_anchor() == ManifestId::null() {
                // Found a genesis manifest!
                let author = manifest.author();

                if let Some(ref existing_root) = discovered_root {
                    if existing_root != author {
                        // UNIQUENESS OF TITLE VIOLATION:
                        // This graph claims to anchor to two different people.
                        return Err(AksharaError::Integrity(
                            crate::base::error::IntegrityError::UnauthorizedSigner(
                                "Conflict of Title: identity graph anchors to multiple root keys"
                                    .to_string(),
                            ),
                        ));
                    }
                } else {
                    discovered_root = Some(author.clone());
                }
            } else {
                // Not a genesis, keep walking parents
                for parent_id in manifest.parents() {
                    queue.push_back(*parent_id);
                }
            }
        }

        discovered_root.ok_or_else(|| {
            AksharaError::Integrity(crate::base::error::IntegrityError::UnauthorizedSigner(
                "Could not find genesis manifest in the identity graph chain".to_string(),
            ))
        })
    }

    pub async fn audit_manifest(
        &self,
        manifest: &Manifest,
        expected_graph_id: Option<&GraphId>,
    ) -> Result<(), AksharaError> {
        let span = span!(Level::DEBUG, "audit_manifest", id = ?manifest.id());
        let _enter = span.enter();

        // GRAPH ID CHECK: Reject manifests from a different graph.
        // This prevents a malicious peer from injecting valid manifests
        // from a different graph during sync.
        if let Some(expected) = expected_graph_id
            && manifest.graph_id() != *expected
        {
            return Err(crate::base::error::AksharaError::Integrity(
                crate::base::error::IntegrityError::GraphIdMismatch(manifest.graph_id(), *expected),
            ));
        }

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
