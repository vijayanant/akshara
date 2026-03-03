use crate::base::address::{BlockId, ManifestId};
use crate::base::crypto::{GraphKey, SigningPublicKey};
use crate::base::error::{IntegrityError, SovereignError};
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
    /// at the moment of the provided Identity Anchor.
    pub async fn verify_authority(
        &self,
        signer: &SigningPublicKey,
        anchor: &ManifestId,
        expected_root_key: &SigningPublicKey,
    ) -> Result<(), SovereignError> {
        let span = span!(Level::DEBUG, "verify_authority", signer = ?signer, anchor = ?anchor);
        let _enter = span.enter();

        // 1. GENESIS PROTECTION: The Null Anchor represents the root of all trust.
        // A Genesis manifest is only valid if signed by the Expected Master Root Key.
        if anchor == &ManifestId::null() {
            if signer == expected_root_key {
                return Ok(());
            } else {
                return Err(SovereignError::Integrity(
                    IntegrityError::UnauthorizedSigner(
                        "Genesis manifest must be signed by the Master Root Key".to_string(),
                    ),
                ));
            }
        }

        // 2. Load the Identity Manifest at the anchor
        let manifest = self.store.get_manifest(anchor).await?.ok_or_else(|| {
            SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                "Identity Anchor {}",
                anchor
            )))
        })?;

        // 3. Walk the graph to find the credential registration
        let walker = GraphWalker::new(self.store, expected_root_key.clone());
        let identity_key = GraphKey::new([0u8; 32]);

        let devices_root = manifest.content_root();

        // Path matches our Specification: /credentials/<pubkey_hex>
        let path = format!("credentials/{}", signer.to_hex());

        let resolution_result = walker
            .resolve_path(devices_root, &path, &identity_key)
            .await;

        match resolution_result {
            Ok(addr) => {
                let block_id = BlockId::try_from(addr)?;
                let block = self.store.get_block(&block_id).await?.ok_or_else(|| {
                    SovereignError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Credential Block {}",
                        block_id
                    )))
                })?;

                let block_type = block.block_type();
                if *block_type == BlockType::AksharaRevocationV1 {
                    return Err(SovereignError::Integrity(
                        IntegrityError::UnauthorizedSigner("Signer has been revoked".to_string()),
                    ));
                }

                debug!("Signer authority verified via identity graph walk");
                Ok(())
            }
            Err(_) => Err(SovereignError::Integrity(
                IntegrityError::UnauthorizedSigner(
                    "Signer not found in authorized credentials list".to_string(),
                ),
            )),
        }
    }
}
