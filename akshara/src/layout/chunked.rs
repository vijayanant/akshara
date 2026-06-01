use crate::error::{Error, Result};
use crate::layout::{BlockLayout, GraphStoreExt};
use akshara_aadhaara::{
    Address, AksharaError, Block, BlockType, GraphId, GraphKey, GraphStore, SecretIdentity,
};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ChunkedLayout;

static CHUNK_SIZE: AtomicUsize = AtomicUsize::new(1024 * 1024); // Default 1MB chunks

impl ChunkedLayout {
    pub fn set_chunk_size(size: usize) {
        CHUNK_SIZE.store(size, Ordering::Relaxed);
    }

    pub fn get_chunk_size() -> usize {
        CHUNK_SIZE.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl BlockLayout<Vec<u8>> for ChunkedLayout {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &Vec<u8>,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> std::result::Result<Address, AksharaError> {
        let chunk_size = Self::get_chunk_size();
        let (index_block, chunk_blocks) = decompose(value, chunk_size, graph_id, key, signer)
            .map_err(|e| match e {
                Error::Protocol(pe) => pe,
                other => AksharaError::InternalError(other.to_string()),
            })?;

        for block in chunk_blocks {
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
    ) -> std::result::Result<Vec<u8>, AksharaError> {
        let index_plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let chunk_addresses: Vec<Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;

        let mut chunk_plaintexts = Vec::new();
        for addr in chunk_addresses {
            let plaintext = store.get_decrypted_block(&addr, graph_id, key).await?;
            chunk_plaintexts.push(plaintext);
        }

        let data = reassemble(&index_plaintext, chunk_plaintexts)
            .map_err(|e| AksharaError::InternalError(e.to_string()))?;

        Ok(data)
    }
}

/// Decomposes a raw byte slice into a set of chunk blocks and a root index block.
pub fn decompose(
    data: &[u8],
    chunk_size: usize,
    graph_id: &GraphId,
    key: &GraphKey,
    signer: &SecretIdentity,
) -> Result<(Block, Vec<Block>)> {
    let mut chunk_blocks = Vec::new();
    let mut chunk_addresses = Vec::new();
    for chunk in data.chunks(chunk_size) {
        let plaintext = akshara_aadhaara::to_canonical_bytes(&chunk.to_vec())
            .map_err(|e| Error::Internal(format!("Serialization failed: {}", e)))?;
        let block = Block::new(
            *graph_id,
            plaintext,
            BlockType::AksharaDataV1,
            vec![],
            key,
            signer,
        )
        .map_err(Error::Protocol)?;
        chunk_addresses.push(Address::from(block.id()));
        chunk_blocks.push(block);
    }

    let index_plaintext = akshara_aadhaara::to_canonical_bytes(&chunk_addresses)
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

    Ok((index_block, chunk_blocks))
}

/// Reassembles a raw byte slice from a decrypted index block and decrypted chunk blocks.
pub fn reassemble(index_plaintext: &[u8], chunk_plaintexts: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let chunk_addresses: Vec<Address> = akshara_aadhaara::from_canonical_bytes(index_plaintext)
        .map_err(|e| Error::Internal(format!("Deserialization failed: {}", e)))?;

    if chunk_addresses.len() != chunk_plaintexts.len() {
        return Err(Error::Internal("Chunk count mismatch".to_string()));
    }

    let mut assembled = Vec::new();
    for plaintext in chunk_plaintexts {
        let chunk_data: Vec<u8> = akshara_aadhaara::from_canonical_bytes(&plaintext)
            .map_err(|e| Error::Internal(format!("Deserialization failed: {}", e)))?;
        assembled.extend_from_slice(&chunk_data);
    }
    Ok(assembled)
}
