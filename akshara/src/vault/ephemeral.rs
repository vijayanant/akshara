use tokio::sync::Mutex;
use zeroize::Zeroizing;

use akshara_aadhaara::{
    AksharaSigner, GraphDescriptor, GraphId, GraphKey, IdentityGraph, Lakshana, ManifestId,
    SecretIdentity, Signature,
};

use super::Vault;
use crate::error::{Error, Result, VaultError};

pub struct EphemeralVault {
    mnemonic: Mutex<Option<Zeroizing<String>>>,
    passphrase: Option<Zeroizing<String>>,
    anchor: Mutex<ManifestId>,
}

impl EphemeralVault {
    pub fn new(passphrase: Option<String>) -> Self {
        Self {
            mnemonic: Mutex::new(None),
            passphrase: passphrase.map(Zeroizing::new),
            anchor: Mutex::new(ManifestId::null()),
        }
    }

    fn passphrase(&self) -> &str {
        self.passphrase.as_deref().map(|s| s.as_str()).unwrap_or("")
    }
}

impl Default for EphemeralVault {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait::async_trait]
impl Vault for EphemeralVault {
    async fn initialize(&self, mnemonic: Option<String>) -> Result<String> {
        let mut stored = self.mnemonic.lock().await;
        if stored.is_some() {
            return Ok("existing".to_string());
        }

        let mnemonic = match mnemonic {
            Some(m) => m,
            None => SecretIdentity::generate_mnemonic().map_err(Error::Protocol)?,
        };

        *stored = Some(Zeroizing::new(mnemonic));
        Ok("created".to_string())
    }

    fn is_initialized(&self) -> bool {
        self.mnemonic
            .try_lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    async fn derive_graph_key(&self, graph_id: &GraphId) -> Result<GraphKey> {
        let identity = self.get_identity(None).await?;
        identity.derive_graph_key(graph_id).map_err(Error::Protocol)
    }

    async fn derive_discovery_id(&self, graph_id: &GraphId) -> Result<Lakshana> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
            .map_err(Error::Protocol)?;
        master
            .derive_discovery_id(graph_id)
            .map_err(Error::Protocol)
    }

    async fn derive_keyring_secret(&self, version: u32) -> Result<GraphKey> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
            .map_err(Error::Protocol)?;
        master
            .derive_keyring_secret(version)
            .map_err(Error::Protocol)
    }

    async fn get_identity_id(&self) -> Result<GraphId> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
            .map_err(Error::Protocol)?;
        master.identity_id().map_err(Error::Protocol)
    }

    async fn get_identity_lakshana(&self) -> Result<Lakshana> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
            .map_err(Error::Protocol)?;
        master.derive_identity_lakshana().map_err(Error::Protocol)
    }

    async fn list_resources(
        &self,
        store: &(dyn akshara_aadhaara::GraphStore + Send + Sync),
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
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;

        if let Some(gid) = graph_id {
            let master =
                akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
                    .map_err(Error::Protocol)?;
            master
                .derive_child("m/44'/999'/0'/1'/0'", Some(gid))
                .map_err(Error::Protocol)
        } else {
            SecretIdentity::from_mnemonic(mnemonic, self.passphrase()).map_err(|e| {
                Error::Vault(VaultError::KeyNotFound(format!(
                    "Identity derivation failed: {}",
                    e
                )))
            })
        }
    }

    async fn get_executive_identity(&self) -> Result<SecretIdentity> {
        let stored = self.mnemonic.lock().await;
        let mnemonic = stored.as_ref().ok_or_else(|| {
            Error::Vault(VaultError::KeyNotFound("Vault not initialized".to_string()))
        })?;

        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(mnemonic, self.passphrase())
            .map_err(Error::Protocol)?;
        master
            .derive_child("m/44'/999'/0'/1'/0'", None)
            .map_err(Error::Protocol)
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

    fn clear(&self) {
        if let Ok(mut stored) = self.mnemonic.try_lock() {
            *stored = None;
        }
    }
}

impl Drop for EphemeralVault {
    fn drop(&mut self) {
        // Zeroize on drop handled via Mutex<Option<Zeroizing<String>>>
    }
}
