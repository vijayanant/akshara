use crate::error::{Error, Result};
use crate::layout::{BlockLayout, GraphStoreExt};
use akshara_aadhaara::{
    Address, AksharaError, Block, BlockType, GraphId, GraphKey, GraphStore, SecretIdentity,
};
use async_trait::async_trait;
use std::collections::BTreeMap;

pub struct CollectionLayout;

#[async_trait]
impl<T> BlockLayout<Vec<T>> for CollectionLayout
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync,
{
    async fn serialize<S: GraphStore + ?Sized>(
        value: &Vec<T>,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> std::result::Result<Address, AksharaError> {
        let mut item_bytes = Vec::with_capacity(value.len());
        for item in value {
            let bytes = akshara_aadhaara::to_canonical_bytes(item)?;
            item_bytes.push(bytes);
        }

        let (index_block, data_blocks) =
            decompose(&item_bytes, graph_id, key, signer).map_err(|e| match e {
                Error::Protocol(pe) => pe,
                other => AksharaError::InternalError(other.to_string()),
            })?;

        for block in data_blocks {
            store.put_block(&block).await?;
        }
        store.put_block(&index_block).await?;

        Ok(Address::from(index_block.id()))
    }

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> std::result::Result<Vec<T>, AksharaError> {
        let index_plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let index_map: BTreeMap<String, Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;

        let mut item_plaintexts = Vec::new();
        for (_k, addr) in index_map {
            let plaintext = store.get_decrypted_block(&addr, graph_id, key).await?;
            item_plaintexts.push(plaintext);
        }

        let assembled_bytes = reassemble(&index_plaintext, item_plaintexts)
            .map_err(|e| AksharaError::InternalError(e.to_string()))?;

        let mut items = Vec::with_capacity(assembled_bytes.len());
        for bytes in assembled_bytes {
            let item: T = akshara_aadhaara::from_canonical_bytes(&bytes)?;
            items.push(item);
        }

        Ok(items)
    }
}

/// Decomposes a list of serialized items into a set of item blocks and a root index block.
pub fn decompose(
    item_bytes: &[Vec<u8>],
    graph_id: &GraphId,
    key: &GraphKey,
    signer: &SecretIdentity,
) -> Result<(Block, Vec<Block>)> {
    let keys = generate_fractional_keys(item_bytes.len());
    let mut index_map = BTreeMap::new();
    let mut data_blocks = Vec::new();

    for (i, item) in item_bytes.iter().enumerate() {
        let block = Block::new(
            *graph_id,
            item.clone(),
            BlockType::AksharaDataV1,
            vec![],
            key,
            signer,
        )
        .map_err(Error::Protocol)?;
        index_map.insert(keys[i].clone(), Address::from(block.id()));
        data_blocks.push(block);
    }

    let index_plaintext = akshara_aadhaara::to_canonical_bytes(&index_map)
        .map_err(|e| Error::Internal(format!("Serialization failed: {}", e)))?;
    let index_block = Block::new(
        *graph_id,
        index_plaintext,
        BlockType::AksharaIndexV1,
        vec![],
        key,
        signer,
    )
    .map_err(Error::Protocol)?;

    Ok((index_block, data_blocks))
}

/// Reassembles a list of serialized items from a decrypted index block and decrypted item blocks.
pub fn reassemble(index_plaintext: &[u8], item_plaintexts: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let index_map: BTreeMap<String, Address> =
        akshara_aadhaara::from_canonical_bytes(index_plaintext)
            .map_err(|e| Error::Internal(format!("Deserialization failed: {}", e)))?;

    if index_map.len() != item_plaintexts.len() {
        return Err(Error::Internal(
            "Collection item count mismatch".to_string(),
        ));
    }

    Ok(item_plaintexts)
}

/// Helper to generate fractional index keys.
pub fn generate_fractional_keys(count: usize) -> Vec<String> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        keys.push(format!("a{:04}", i));
    }
    keys
}
