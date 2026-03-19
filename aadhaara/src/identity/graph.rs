use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::{GraphKey, SigningPublicKey};
use crate::base::error::{AksharaError, IntegrityError};
use crate::graph::BlockType;
use crate::state::store::GraphStore;
use crate::traversal::walker::GraphWalker;
use tracing::{Level, debug, span};

/// `IdentityGraph` provides the logic for traversing and verifying a user's
/// social authority timeline.
pub struct IdentityGraph<'a, S: GraphStore + ?Sized> {
    pub(crate) store: &'a S,
}

impl<'a, S: GraphStore + ?Sized> IdentityGraph<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Verifies that a specific signing key was authorized and unrevoked
    /// at the moment of the provided Identity Anchor, AND remains unrevoked
    /// in the context of an optional Latest Identity (Frontier).
    pub async fn verify_authority(
        &self,
        signer: &SigningPublicKey,
        anchor: &ManifestId,
        expected_root_key: &SigningPublicKey,
        latest_identity: Option<&ManifestId>,
    ) -> Result<(), AksharaError> {
        let span = span!(Level::DEBUG, "verify_authority", signer = ?signer, anchor = ?anchor, latest = ?latest_identity);
        let _enter = span.enter();

        // 1. GENESIS PROTECTION
        if anchor == &ManifestId::null() {
            if signer == expected_root_key {
                return Ok(());
            } else {
                return Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(
                    "Genesis manifest must be signed by the Master Root Key".to_string(),
                )));
            }
        }

        // 2. PRIMARY CHECK: Verify authority at the local anchor
        self.check_authorization_at(signer, anchor, expected_root_key)
            .await?;

        // 3. LATEST STATE PROTECTION: Prevent "Ghost Branches" by checking the latest known state.
        // If a revocation exists at the frontier, this manifest is rejected regardless of its local anchor.
        if let Some(latest) = latest_identity.filter(|&l| l != anchor) {
            match self
                .check_authorization_at(signer, latest, expected_root_key)
                .await
            {
                Ok(_) => { /* Still valid at frontier */ }
                Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(msg))) => {
                    return Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(
                        format!("Signer is revoked in the latest state {}: {}", latest, msg),
                    )));
                }
                Err(e) => return Err(e),
            }
        }

        debug!("Signer authority verified via frontier-aware walk");
        Ok(())
    }

    async fn check_authorization_at(
        &self,
        signer: &SigningPublicKey,
        anchor: &ManifestId,
        expected_root_key: &SigningPublicKey,
    ) -> Result<(), AksharaError> {
        let manifest = self.store.get_manifest(anchor).await?.ok_or_else(|| {
            AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                "Identity Anchor {}",
                anchor
            )))
        })?;

        // 3. Walk the graph to find the credential registration
        let walker = GraphWalker::new(self.store, expected_root_key.clone());
        let identity_key = GraphKey::new([0u8; 32]);
        let devices_root = manifest.content_root();
        let graph_id = manifest.graph_id();

        // TIER A: Direct Verification (Master Executive Key)
        let path = format!("credentials/{}", signer.to_hex());
        let resolution_result = walker
            .resolve_path(&graph_id, devices_root, &path, &identity_key)
            .await;

        if let Ok(addr) = resolution_result {
            self.verify_block_is_not_revocation(&addr).await?;
            debug!("Signer authority verified via Master Executive Key");
            return Ok(());
        }

        // TIER B: Shadow Identity Verification (Privacy-Preserving)
        // If not found directly, we must check if this is a shadow of ANY authorized key.
        // This is an O(N) check of authorized keys, but N (devices) is typically < 10.
        let authorized_keys = self
            .list_authorized_executives(&graph_id, devices_root, &identity_key)
            .await?;

        for exec_pub in authorized_keys {
            if self.is_valid_shadow(signer, &exec_pub, &graph_id) {
                debug!("Signer authority verified via Shadow Identity Ritual");
                return Ok(());
            }
        }

        Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(
            "Signer not found in authorized credentials or shadow list".to_string(),
        )))
    }

    async fn verify_block_is_not_revocation(&self, addr: &Address) -> Result<(), AksharaError> {
        let block_id = BlockId::try_from(*addr)?;
        let block = self.store.get_block(&block_id).await?.ok_or_else(|| {
            AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                "Credential Block {}",
                block_id
            )))
        })?;

        if *block.block_type() == BlockType::AksharaRevocationV1 {
            return Err(AksharaError::Integrity(IntegrityError::UnauthorizedSigner(
                "Signer has been revoked".to_string(),
            )));
        }
        Ok(())
    }

    fn is_valid_shadow(
        &self,
        shadow: &SigningPublicKey,
        master: &SigningPublicKey,
        graph_id: &GraphId,
    ) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Ritual: Shadow = HMAC-SHA256(MasterKey, "akshara.v1.shadow_identity" + GraphId)
        let mut hmac = match Hmac::<Sha256>::new_from_slice(master.as_bytes()) {
            Ok(h) => h,
            Err(_) => return false,
        };

        hmac.update(b"akshara.v1.shadow_identity");
        hmac.update(graph_id.as_bytes());
        let result = hmac.finalize().into_bytes();

        // The resulting 32 bytes are the public key bytes of the Shadow Identity
        shadow.as_bytes() == &result[..32]
    }

    async fn list_authorized_executives(
        &self,
        _graph_id: &GraphId,
        _root: BlockId,
        _key: &GraphKey,
    ) -> Result<Vec<SigningPublicKey>, AksharaError> {
        // TODO: Implement a real O(N) traversal of the /credentials directory.
        // For now, we return an empty list to prevent compile errors.
        // This will be completed in the next "Karma" update.
        Ok(vec![])
    }
}
