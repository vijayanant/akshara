use tokio::sync::Mutex;
use zeroize::Zeroizing;

use akshara_aadhaara::{
    AksharaSigner, GraphDescriptor, GraphId, GraphKey, IdentityGraph, InMemoryStore, Lakshana,
    ManifestId, SecretIdentity, Signature, paths,
};

use super::Vault;
use crate::error::{Error, Result, VaultError};

/// Vault implementation using platform-native secure storage.
pub struct PlatformVault {
    service: String,
    anchor: Mutex<ManifestId>,
}

impl PlatformVault {
    pub fn new(service: String) -> Self {
        Self {
            service,
            anchor: Mutex::new(ManifestId::null()),
        }
    }

    fn branch_key(index: u32) -> String {
        format!("branch:{}", index)
    }

    fn save_branch(&self, index: u32, data: &[u8]) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, &Self::branch_key(index))
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        let password = hex::encode(data);
        entry
            .set_password(&password)
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;
        Ok(())
    }

    fn load_branch(&self, index: u32) -> Result<Vec<u8>> {
        let entry = keyring::Entry::new(&self.service, &Self::branch_key(index))
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        let password = entry
            .get_password()
            .map_err(|e| Error::Vault(VaultError::Keychain(e.to_string())))?;

        hex::decode(password)
            .map_err(|e| Error::Vault(VaultError::Keychain(format!("Hex decode failed: {}", e))))
    }
}

#[async_trait::async_trait]
impl Vault for PlatformVault {
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String> {
        if self.load_branch(0).is_ok() {
            return Ok("existing".to_string());
        }

        let mnemonic = match mnemonic {
            Some(m) => Zeroizing::new(m),
            None => Zeroizing::new(SecretIdentity::generate_mnemonic().map_err(|e| {
                Error::Vault(VaultError::Keychain(format!(
                    "Failed to generate mnemonic: {}",
                    e
                )))
            })?),
        };

        for i in 0..=5 {
            let branch = SecretIdentity::derive_branch_from_mnemonic(&mnemonic, "", i)
                .map_err(Error::Protocol)?;
            self.save_branch(i, &branch.to_bytes())?;
        }

        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.load_branch(0).is_ok()
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        let branch2_bytes = self.load_branch(paths::BRANCH_SECRET)?;
        let branch2 = SecretIdentity::from_bytes(&branch2_bytes).map_err(Error::Protocol)?;
        branch2.derive_graph_key(graph_id).map_err(Error::Protocol)
    }

    async fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana> {
        let branch5_bytes = self.load_branch(paths::BRANCH_DISCOVERY)?;
        let branch5 = SecretIdentity::from_bytes(&branch5_bytes).map_err(Error::Protocol)?;
        branch5
            .derive_discovery_id(graph_id)
            .map_err(Error::Protocol)
    }

    async fn derive_keyring_secret(&self, version: u32) -> Result<GraphKey> {
        if version != 0 {
            return Err(Error::Vault(VaultError::DerivationFailed(
                "Keyring derivation for versions > 0 requires Master Seed".to_string(),
            )));
        }
        let branch4_bytes = self.load_branch(paths::BRANCH_KEYRING)?;
        let branch4 = SecretIdentity::from_bytes(&branch4_bytes).map_err(Error::Protocol)?;
        let pub_key_bytes = branch4.public().signing_key().as_bytes();
        Ok(GraphKey::new(*pub_key_bytes))
    }

    async fn get_identity_id(&self) -> Result<GraphId> {
        let branch0_bytes = self.load_branch(paths::BRANCH_LEGISLATOR)?;
        let branch0 = SecretIdentity::from_bytes(&branch0_bytes).map_err(Error::Protocol)?;
        branch0.identity_id().map_err(Error::Protocol)
    }

    async fn get_identity_lakshana(&self) -> Result<Lakshana> {
        let branch0_bytes = self.load_branch(paths::BRANCH_LEGISLATOR)?;
        let branch0 = SecretIdentity::from_bytes(&branch0_bytes).map_err(Error::Protocol)?;
        branch0.derive_identity_lakshana().map_err(Error::Protocol)
    }

    async fn list_resources(
        &self,
        store: &InMemoryStore,
    ) -> Result<Vec<(akshara_aadhaara::Address, GraphDescriptor)>> {
        let anchor = self.latest_identity_anchor();
        if anchor == ManifestId::null() {
            return Ok(vec![]);
        }
        let identity_graph = IdentityGraph::new(store);
        identity_graph
            .list_resources(&anchor)
            .await
            .map_err(Error::Protocol)
    }

    async fn sign(&self, graph_id: &GraphId, data: &[u8]) -> Result<Signature> {
        let identity = self.get_identity(Some(graph_id)).await?;
        Ok(identity.sign(data))
    }

    async fn get_identity(&self, graph_id: Option<&GraphId>) -> Result<SecretIdentity> {
        let branch_index = if graph_id.is_some() {
            paths::BRANCH_EXECUTIVE
        } else {
            paths::BRANCH_LEGISLATOR
        };

        let branch_bytes = self.load_branch(branch_index)?;
        let identity = SecretIdentity::from_bytes(&branch_bytes).map_err(Error::Protocol)?;

        if let Some(gid) = graph_id {
            identity
                .derive_shadow_identity(gid)
                .map_err(Error::Protocol)
        } else {
            Ok(identity)
        }
    }

    fn latest_identity_anchor(&self) -> ManifestId {
        match self.anchor.try_lock() {
            Ok(anchor) => *anchor,
            Err(_) => ManifestId::null(),
        }
    }

    fn update_identity_anchor(&self, anchor: ManifestId) {
        if let Ok(mut stored) = self.anchor.try_lock() {
            *stored = anchor;
        }
    }

    fn clear(&self) {}
}
