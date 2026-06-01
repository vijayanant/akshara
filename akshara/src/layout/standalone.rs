use akshara_aadhaara::{
    Address, AksharaError, Block, BlockType, GraphId, GraphKey, GraphStore, SecretIdentity,
};
use async_trait::async_trait;

use crate::layout::{BlockLayout, GraphStoreExt};

pub struct StandaloneLayout;

#[async_trait]
impl<T> BlockLayout<T> for StandaloneLayout
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync,
{
    async fn serialize<S: GraphStore + ?Sized>(
        value: &T,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> std::result::Result<Address, AksharaError> {
        let plaintext = akshara_aadhaara::to_canonical_bytes(value)?;
        let block = Block::new(
            *graph_id,
            plaintext,
            BlockType::AksharaDataV1,
            vec![],
            key,
            signer,
        )?;
        store.put_block(&block).await?;
        Ok(Address::from(block.id()))
    }

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> std::result::Result<T, AksharaError> {
        let plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let value = akshara_aadhaara::from_canonical_bytes(&plaintext)?;
        Ok(value)
    }
}
