#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::base::address::{Address, BlockId, GraphId, ManifestId};
use crate::base::crypto::GraphKey;
use crate::graph::{Block, BlockType, Manifest};
use crate::identity::types::SecretIdentity;
use crate::state::in_memory_store::InMemoryStore;
use crate::state::store::GraphStore;
use crate::traversal::index_builder::IndexBuilder;
use std::sync::Arc;

/// `TestFactory` provides ergonomic methods for creating Akshara primitives
/// during testing. It manages a local identity and store to minimize boilerplate.
pub struct TestFactory {
    pub identity: SecretIdentity,
    pub store: Arc<InMemoryStore>,
    pub graph_id: GraphId,
    pub graph_key: GraphKey,
    pub anchor: ManifestId,
}

impl TestFactory {
    /// Initializes a fresh factory with a random identity and an empty store.
    pub async fn new() -> Self {
        let mut rng = rand::rngs::OsRng;
        let identity = SecretIdentity::generate(&mut rng).unwrap();
        let store = Arc::new(InMemoryStore::new());
        let graph_id = GraphId::new();
        let graph_key = GraphKey::generate(&mut rng);

        Self {
            identity,
            store,
            graph_id,
            graph_key,
            anchor: ManifestId::null(),
        }
    }

    /// Creates a factory anchored to a valid Identity Graph.
    pub async fn with_anchor() -> Self {
        let mut factory = Self::new().await;
        factory.anchor = factory.create_identity_anchor().await;
        factory
    }

    /// Creates a data block with the given plaintext.
    pub async fn create_block(&self, data: &[u8]) -> Block {
        let block = Block::new(
            self.graph_id,
            data.to_vec(),
            BlockType::AksharaDataV1,
            vec![],
            &self.graph_key,
            &self.identity,
        )
        .unwrap();

        self.store.put_block(&block).await.unwrap();
        block
    }

    /// Creates a manifest with sensible defaults.
    pub async fn create_manifest(&self, root: BlockId, parents: Vec<ManifestId>) -> Manifest {
        let manifest = Manifest::new(
            self.graph_id,
            root,
            parents,
            self.anchor,
            Address::null(), // Default schema anchor
            &self.identity,
            None, // Default to no authority proof
        );

        self.store.put_manifest(&manifest).await.unwrap();
        manifest
    }

    /// Creates a manifest with a specific schema anchor.
    pub async fn create_manifest_with_schema(
        &self,
        root: BlockId,
        parents: Vec<ManifestId>,
        schema: Address,
    ) -> Manifest {
        let manifest = Manifest::new(
            self.graph_id,
            root,
            parents,
            self.anchor,
            schema,
            &self.identity,
            None,
        );

        self.store.put_manifest(&manifest).await.unwrap();
        manifest
    }

    /// Creates a genesis manifest for the factory's graph.
    pub async fn create_genesis(&self) -> Manifest {
        self.create_manifest(self.dummy_root(), vec![]).await
    }

    /// Returns a dummy root CID (all FFs) for tests that don't care about content.
    pub fn dummy_root(&self) -> BlockId {
        BlockId::from_sha256(&[0xFFu8; 32])
    }

    /// Internal helper to bootstrap the identity graph.
    pub async fn create_identity_anchor(&self) -> ManifestId {
        use crate::identity::graph::IDENTITY_GRAPH_KEY;

        let signer_hex = self.identity.public().signing_key().to_hex();

        let auth_block = Block::new(
            GraphId::new(),
            vec![],
            BlockType::AksharaAuthV1,
            vec![],
            &IDENTITY_GRAPH_KEY,
            &self.identity,
        )
        .unwrap();
        self.store.put_block(&auth_block).await.unwrap();

        let mut builder = IndexBuilder::new();
        builder
            .insert(
                &format!("credentials/{}", signer_hex),
                Address::from(auth_block.id()),
            )
            .unwrap();

        let root_index_id = builder
            .build(
                self.graph_id,
                self.store.as_ref(),
                &self.identity,
                &IDENTITY_GRAPH_KEY,
            )
            .await
            .unwrap();

        let genesis_manifest = Manifest::new(
            self.graph_id,
            root_index_id,
            vec![],
            ManifestId::null(),
            Address::null(),
            &self.identity,
            None,
        );

        self.store.put_manifest(&genesis_manifest).await.unwrap();
        genesis_manifest.id()
    }
}
