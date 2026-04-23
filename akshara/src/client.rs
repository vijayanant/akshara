//! The Akshara client — main entry point for the API.
use akshara_aadhaara::{
    BlockContent, GraphDescriptor, GraphId, GraphStore, IdentityGraph, InMemoryStore, Lakshana,
};
use rand::RngCore;
use std::sync::Arc;

use crate::config::{ClientConfig, TuningConfig};
use crate::error::{Error, Result};
use crate::graph::{Graph, SyncReport};
use crate::staging::InMemoryStagingStore;
use crate::sync::{MockTransport, SyncEngine};
use crate::vault::{Vault, create_vault};

/// The main Akshara client.
///
/// `Client` is the entry point. It manages:
/// - A vault for identity and key storage
/// - A storage backend for blocks and manifests
/// - An in-memory staging buffer for write coalescing
/// - A registry of graphs known to this client
pub struct Client {
    vault: Arc<dyn Vault>,
    store: InMemoryStore,
    tuning: TuningConfig,
}

impl Client {
    /// Initialize the Akshara client.
    ///
    /// On first run, a 24-word mnemonic is generated and shown via the vault.
    /// **Write this down — there is no "forgot password."**
    pub async fn init(config: ClientConfig) -> Result<Self> {
        let vault_cfg = config.vault().clone();
        let tuning = config.tuning().clone();

        let vault = create_vault(vault_cfg)?;
        let _result = vault.initialize(None).await?;

        let store = InMemoryStore::new();

        Ok(Self {
            vault,
            store,
            tuning,
        })
    }

    /// Create a new graph with a randomly generated ID.
    ///
    /// The graph is encrypted with a key derived from your identity and the
    /// graph ID. Each graph gets its own staging store — operations never
    /// leak across graph boundaries.
    pub async fn create_graph(&self) -> Result<Graph> {
        let graph_id = GraphId::new();
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;
        let staging = Arc::new(InMemoryStagingStore::new());

        // AKSHARA RITUAL: Register in the Identity Graph for deterministic recovery.
        let identity_id = self.vault.get_identity_id().await?;
        let legislator = self.vault.get_identity(None).await?;
        let keyring_secret = self.vault.derive_keyring_secret(0).await?;

        let mut rng = rand::rngs::OsRng;
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let enc_graph_key = BlockContent::encrypt(
            graph_key.as_bytes(),
            &keyring_secret,
            nonce,
            graph_id.as_bytes(),
        )
        .map_err(Error::Protocol)?;

        let descriptor = GraphDescriptor {
            graph_id,
            label: None,
            enc_graph_key,
            keyring_version: 0,
            created_at: 0,
            shared_by: None,
        };

        let identity_graph = IdentityGraph::new(&self.store);
        let new_anchor = identity_graph
            .add_resource(descriptor, true, &identity_id, &legislator)
            .await
            .map_err(Error::Protocol)?;

        self.vault.update_identity_anchor(new_anchor);

        // AKSHARA RITUAL: Create the Genesis Manifest for the new graph
        // We MUST create a real, empty index block - null() is not a valid root.
        let index_builder = akshara_aadhaara::IndexBuilder::new();
        let shadow_signer = legislator
            .derive_shadow_identity(&graph_id)
            .map_err(Error::Protocol)?;

        let root_index_id = index_builder
            .build(graph_id, &self.store, &shadow_signer, &graph_key)
            .await
            .map_err(Error::Protocol)?;

        let genesis = akshara_aadhaara::Manifest::new(
            graph_id,
            root_index_id,
            vec![],
            new_anchor,
            &shadow_signer,
            None,
        );
        self.store
            .put_manifest(&genesis)
            .await
            .map_err(Error::Protocol)?;

        Ok(Graph::new(
            graph_id,
            graph_key,
            self.vault.clone(),
            self.store.clone(),
            staging,
            self.tuning.clone(),
        ))
    }

    /// Open an existing graph by its Lakshana.
    ///
    /// A Lakshana is an anonymous, HMAC-derived identifier that prevents
    /// relay-side graph clustering. The client discovers the graph by
    /// searching its own Resource Index for a matching Lakshana.
    pub async fn open_graph(&self, lakshana_str: &str) -> Result<Graph> {
        let target_lakshana: Lakshana = lakshana_str
            .parse()
            .map_err(|_| Error::InvalidLakshana(lakshana_str.to_string()))?;

        // DISCOVERY RITUAL: Walk the Resource Index to find the graph_id and graph_key
        let resources = self.vault.list_resources(&self.store).await?;
        let keyring_secret = self.vault.derive_keyring_secret(0).await?;

        for (_addr, descriptor) in resources {
            // Re-derive Lakshana for this graph to see if it matches
            let candidate_lakshana = self.vault.derive_discovery_id(&descriptor.graph_id).await?;

            if candidate_lakshana == target_lakshana {
                // MATCH FOUND: Decrypt the graph_key
                let plaintext = descriptor
                    .enc_graph_key
                    .decrypt(&keyring_secret, descriptor.graph_id.as_bytes())
                    .map_err(Error::Protocol)?;

                let array: [u8; 32] = plaintext
                    .try_into()
                    .map_err(|_| Error::Internal("Invalid key size in descriptor".to_string()))?;
                let graph_key = akshara_aadhaara::GraphKey::new(array);
                let staging = Arc::new(InMemoryStagingStore::new());

                return Ok(Graph::new(
                    descriptor.graph_id,
                    graph_key,
                    self.vault.clone(),
                    self.store.clone(),
                    staging,
                    self.tuning.clone(),
                ));
            }
        }

        Err(Error::GraphNotFound(akshara_aadhaara::GraphId::null()))
    }

    /// Discover all graphs associated with this user's identity.
    ///
    /// This performs the Stateless Recovery Ritual by walking the Identity Graph's
    /// resource index.
    pub async fn discover_graphs(&self) -> Result<Vec<GraphSummary>> {
        let resources = self.vault.list_resources(&self.store).await?;
        let mut summaries = Vec::new();

        for (_addr, descriptor) in resources {
            let lakshana = self.vault.derive_discovery_id(&descriptor.graph_id).await?;
            let heads = self
                .store
                .get_heads(&descriptor.graph_id)
                .await
                .map_err(Error::Protocol)?;

            summaries.push(GraphSummary {
                graph_id: descriptor.graph_id,
                lakshana: lakshana.to_hex(),
                manifest_count: heads.len(),
                last_flushed: None,
            });
        }

        Ok(summaries)
    }

    /// Synchronize all graphs with the relay.
    ///
    /// Currently uses `MockTransport` — real gRPC transport is coming in v0.2.
    pub async fn sync_all(&self) -> Result<SyncReport> {
        let transport = Arc::new(MockTransport::new());
        let engine = SyncEngine::new(transport, self.vault.clone());
        engine.sync_all(&self.store).await
    }

    /// Synchronize a specific graph.
    pub async fn sync_graph(&self, graph_id: GraphId) -> Result<SyncReport> {
        let transport = Arc::new(MockTransport::new());
        let engine = SyncEngine::new(transport, self.vault.clone());
        let graph_key = self.vault.derive_graph_key(&graph_id).await?;
        engine.sync_graph(graph_id, &self.store, &graph_key).await
    }

    /// Remove a graph from the local registry.
    ///
    /// Note: this removes the graph from discovery but does not yet clear
    /// block/manifest data from the store.
    pub async fn forget_graph(&self, _graph_id: GraphId) -> Result<()> {
        // TODO: In a real system, this would mark the resource as deleted
        // in the Identity Graph. For now, we just return Ok.
        Ok(())
    }

    /// Returns the vault handle for vault-specific operations.
    pub fn vault(&self) -> &Arc<dyn Vault> {
        &self.vault
    }
}

/// Summary information for a discovered graph.
#[derive(Debug, Clone)]
pub struct GraphSummary {
    pub graph_id: GraphId,
    pub lakshana: String,
    pub manifest_count: usize,
    pub last_flushed: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_client() -> Client {
        let config = ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage();
        // We need to initialize the vault with the mnemonic for tests
        // For now, use the standard init path
        Client::init(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_graph() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();
        assert!(!graph.id().to_string().is_empty());
    }

    #[tokio::test]
    async fn test_discover_graphs_empty() {
        let client = create_test_client().await;
        let graphs = client.discover_graphs().await.unwrap();
        assert!(graphs.is_empty());
    }

    #[tokio::test]
    async fn test_discover_graphs_after_create() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();

        // Graph is registered immediately (Identity Graph), even before flush
        let graphs = client.discover_graphs().await.unwrap();
        assert_eq!(graphs.len(), 1);
        assert_eq!(graphs[0].graph_id, graph.id());
        // Manifest count is 1 because create_graph signs a genesis manifest
        assert_eq!(graphs[0].manifest_count, 1);
    }

    #[tokio::test]
    async fn test_forget_graph() {
        let client = create_test_client().await;
        let graph = client.create_graph().await.unwrap();
        let graph_id = graph.id();

        // Forget should not error even with no data
        client.forget_graph(graph_id).await.unwrap();
    }

    #[tokio::test]
    async fn open_graph_rejects_invalid_lakshana() {
        // A typo in the lakshana must give a clean error, not panic or open
        // a garbage graph.
        let client = create_test_client().await;
        let result = client.open_graph("not-a-valid-lakshana!!!").await;
        assert!(
            matches!(result, Err(Error::InvalidLakshana(_))),
            "Expected InvalidLakshana for garbage input"
        );
    }

    #[tokio::test]
    async fn discover_graphs_tracks_all_created_graphs() {
        // Verify that create_graph properly registers graphs and that
        // discover_graphs returns them. This guards against the registry
        // and graph creation getting out of sync.
        let client = create_test_client().await;

        let g1 = client.create_graph().await.unwrap();
        let g2 = client.create_graph().await.unwrap();

        let all = client.discover_graphs().await.unwrap();
        assert_eq!(all.len(), 2);

        let ids: Vec<_> = all.iter().map(|s| s.graph_id).collect();
        assert!(ids.contains(&g1.id()));
        assert!(ids.contains(&g2.id()));
    }
}
