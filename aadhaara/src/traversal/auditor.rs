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
    pub(crate) graph_key: Option<crate::base::crypto::GraphKey>,
    /// Memoized identity root keys (anchor -> root_key) to avoid O(N^2) walks.
    pub(crate) memoized_identity_roots:
        std::sync::Arc<std::sync::RwLock<std::collections::HashMap<ManifestId, SigningPublicKey>>>,
    /// Memoized graph legislators (graph_id -> root_key).
    pub(crate) memoized_graph_legislators:
        std::sync::Arc<std::sync::RwLock<std::collections::HashMap<GraphId, SigningPublicKey>>>,
    /// Memoized trusted executives for a given graph.
    pub(crate) memoized_trusted_executives: std::sync::Arc<
        std::sync::RwLock<
            std::collections::HashMap<GraphId, std::collections::HashSet<SigningPublicKey>>,
        >,
    >,
}

impl<'a, S: GraphStore + ?Sized> Auditor<'a, S> {
    /// Creates a new Auditor.
    pub fn new(store: &'a S) -> Self {
        Self {
            store,
            latest_identity: None,
            graph_key: None,
            memoized_identity_roots: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            memoized_graph_legislators: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            memoized_trusted_executives: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    pub fn with_latest_identity(mut self, identity: ManifestId) -> Self {
        self.latest_identity = Some(identity);
        self
    }

    pub fn with_graph_key(mut self, key: crate::base::crypto::GraphKey) -> Self {
        self.graph_key = Some(key);
        self
    }

    /// Discovers the Legislator root key from the manifest's identity graph.
    async fn discover_root_key(
        &self,
        manifest: &Manifest,
    ) -> Result<SigningPublicKey, AksharaError> {
        let anchor = manifest.identity_anchor();

        // 1. Check memoization first
        {
            let cache = self.memoized_identity_roots.read().map_err(|_| {
                AksharaError::InternalError("memoized_identity_roots lock poisoned".to_string())
            })?;
            if let Some(key) = cache.get(&anchor) {
                return Ok(key.clone());
            }
        }

        // 2. Not in cache, perform discovery
        let root_key = if anchor == ManifestId::null() {
            // Genesis manifest: the author IS the root of trust
            manifest.author().clone()
        } else {
            // Non-genesis: walk the identity graph to find the genesis
            self.discover_identity_root_iterative(&anchor).await?
        };

        // 3. Update cache
        {
            let mut cache = self.memoized_identity_roots.write().map_err(|_| {
                AksharaError::InternalError("memoized_identity_roots lock poisoned".to_string())
            })?;
            cache.insert(anchor, root_key.clone());
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

    /// Discovers the root Legislator key for the graph this manifest belongs to.
    async fn discover_graph_legislator(
        &self,
        manifest: &Manifest,
    ) -> Result<SigningPublicKey, AksharaError> {
        let graph_id = manifest.graph_id();

        // 1. Check memoization
        {
            let cache = self.memoized_graph_legislators.read().map_err(|_| {
                AksharaError::InternalError("memoized_graph_legislators lock poisoned".to_string())
            })?;
            if let Some(key) = cache.get(&graph_id) {
                return Ok(key.clone());
            }
        }

        // 2. Discover genesis manifest author
        let genesis_author = self.discover_graph_genesis_iterative(manifest).await?;

        // 3. Update cache
        {
            let mut cache = self.memoized_graph_legislators.write().map_err(|_| {
                AksharaError::InternalError("memoized_graph_legislators lock poisoned".to_string())
            })?;
            cache.insert(graph_id, genesis_author.clone());
        }

        Ok(genesis_author)
    }

    /// Recursively walks the graph's manifest chain to find the genesis author.
    async fn discover_graph_genesis_iterative(
        &self,
        manifest: &Manifest,
    ) -> Result<SigningPublicKey, AksharaError> {
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(manifest.clone());

        let mut visited = std::collections::HashSet::new();
        let mut depth = 0;
        const MAX_GRAPH_DEPTH: usize = 10000;

        while let Some(current_manifest) = queue.pop_front() {
            if !visited.insert(current_manifest.id()) {
                continue;
            }

            depth += 1;
            if depth > MAX_GRAPH_DEPTH {
                return Err(AksharaError::Integrity(
                    crate::base::error::IntegrityError::DepthLimitExceeded(MAX_GRAPH_DEPTH),
                ));
            }

            if current_manifest.parents().is_empty() {
                // Found genesis manifest of the graph!
                // The graph legislator is the root of the genesis signer's identity.
                return self.discover_root_key(&current_manifest).await;
            }

            for parent_id in current_manifest.parents() {
                let parent = self.store.get_manifest(parent_id).await?.ok_or_else(|| {
                    AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Parent manifest {}",
                        parent_id
                    )))
                })?;
                queue.push_back(parent);
            }
        }

        Err(AksharaError::Integrity(
            crate::base::error::IntegrityError::UnauthorizedSigner(
                "Could not find genesis manifest in the graph chain".to_string(),
            ),
        ))
    }

    /// Verifies if a root identity has been delegated authority via an AksharaTrustV1 block.
    async fn verify_trust_delegation(
        &self,
        manifest: &Manifest,
        root_key: &SigningPublicKey,
    ) -> Result<bool, AksharaError> {
        let graph_id = manifest.graph_id();

        // 1. Check memoization
        {
            let cache = self.memoized_trusted_executives.read().map_err(|_| {
                AksharaError::InternalError("memoized_trusted_executives lock poisoned".to_string())
            })?;
            if let Some(set) = cache.get(&graph_id)
                && set.contains(root_key)
            {
                return Ok(true);
            }
        }

        // 2. Genesis manifests cannot have trust delegations (must be signed by legislator)
        if manifest.parents().is_empty() {
            return Ok(false);
        }

        // 3. Scan parent states for a trust block
        use crate::traversal::walker::GraphWalker;
        let walker = GraphWalker::new(self.store);
        let trust_path = format!(".akshara.trust/{}", root_key.to_hex());

        for parent_id in manifest.parents() {
            let parent = self.store.get_manifest(parent_id).await?.ok_or_else(|| {
                AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                    "Parent manifest {}",
                    parent_id
                )))
            })?;

            // Resolve trust path in parent's content_root.
            // We use the graph_key if available, otherwise fallback to well-known identity key.
            let fallback_key = crate::identity::graph::IDENTITY_GRAPH_KEY;
            let key = self.graph_key.as_ref().unwrap_or(&fallback_key);

            if let Ok(addr) = walker
                .resolve_path(&graph_id, parent.content_root(), &trust_path, key)
                .await
            {
                // Verify it's an AksharaTrustV1 block
                let block_id = BlockId::try_from(addr)?;
                if let Ok(Some(block)) = self.store.get_block(&block_id).await
                    && block.block_type() == &crate::graph::BlockType::AksharaTrustV1
                {
                    // SECURITY RITUAL: Only the Legislator can grant trust.
                    let legislator = self.discover_graph_legislator(manifest).await?;
                    if block.author() != &legislator {
                        debug!(
                            "Rejecting trust block at {} - signed by {} instead of legislator {}",
                            addr,
                            block.author().to_hex(),
                            legislator.to_hex()
                        );
                        continue;
                    }

                    // Success! Update cache
                    {
                        let mut cache = self.memoized_trusted_executives.write().map_err(|_| {
                            AksharaError::InternalError(
                                "memoized_trusted_executives lock poisoned".to_string(),
                            )
                        })?;
                        cache
                            .entry(graph_id)
                            .or_insert_with(std::collections::HashSet::new)
                            .insert(root_key.clone());
                    }
                    return Ok(true);
                }
            }
        }

        Ok(false)
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

        // AUTHORITY RITUAL: Determine which key to verify against the identity graph.
        // If an authority_proof is present, this is a shadow identity, and we must
        // verify the MASTER key that delegated the authority.
        let key_to_verify = if let Some(ref proof) = manifest.header.authority_proof {
            let graph_key = self.graph_key.as_ref().ok_or_else(|| {
                AksharaError::Integrity(crate::base::error::IntegrityError::UnauthorizedSigner(
                    "GraphKey required to verify shadow identity proof".to_string(),
                ))
            })?;

            crate::identity::types::SecretIdentity::verify_shadow_certificate(
                manifest.author(),
                &manifest.graph_id(),
                graph_key,
                proof,
            )?
        } else {
            manifest.author().clone()
        };

        let identity_graph = IdentityGraph::new(self.store);
        identity_graph
            .verify_authority(
                &key_to_verify,
                &manifest.identity_anchor(),
                &root_key,
                self.latest_identity.as_ref(),
            )
            .await?;

        // AKSHARA RITUAL (Chain of Title):
        // Verify that this root identity is authorized for THIS graph.
        let graph_legislator = self.discover_graph_legislator(manifest).await?;

        if key_to_verify != graph_legislator {
            // Signer is not the legislator. Check for trust delegation in parent state.
            let is_trusted = self
                .verify_trust_delegation(manifest, &key_to_verify)
                .await?;

            if !is_trusted {
                return Err(AksharaError::Integrity(
                    crate::base::error::IntegrityError::UnauthorizedSigner(
                        "Signer identity is valid, but not authorized for this graph (Chain of Title failure)".to_string(),
                    ),
                ));
            }
        }

        debug!("Manifest fully audited (Integrity + Authority + Chain of Title)");
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
