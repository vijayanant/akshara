//! Pure block layout decomposition and reassembly strategies.

use akshara_aadhaara::{Address, AksharaError, GraphId, GraphKey, GraphStore};
use async_trait::async_trait;

pub mod chunked;
pub mod collection;
pub mod standalone;
pub mod text;

pub use chunked::ChunkedLayout;
pub use collection::CollectionLayout;
pub use standalone::StandaloneLayout;
pub use text::TextLayout;

#[async_trait]
pub trait BlockLayout<T> {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &T,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &akshara_aadhaara::SecretIdentity,
        store: &S,
        prefix_path: &str,
    ) -> std::result::Result<Address, AksharaError>;

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> std::result::Result<T, AksharaError>;
}

#[async_trait]
pub trait GraphStoreExt {
    async fn get_decrypted_block(
        &self,
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
    ) -> std::result::Result<Vec<u8>, AksharaError>;
}

#[async_trait]
impl<S: GraphStore + ?Sized> GraphStoreExt for S {
    async fn get_decrypted_block(
        &self,
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
    ) -> std::result::Result<Vec<u8>, AksharaError> {
        let block_id = akshara_aadhaara::BlockId::try_from(*address)?;
        let block = self.get_block(&block_id).await?.ok_or_else(|| {
            akshara_aadhaara::StoreError::NotFound(format!("Block {} not found in store", block_id))
        })?;
        let plaintext = block.decrypt(graph_id, key)?;
        Ok(plaintext)
    }
}
