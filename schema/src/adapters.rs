use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use akshara_aadhaara::{
    Address, AksharaError, Block, BlockId, BlockType, GraphId, GraphKey, GraphStore, SecretIdentity,
};

#[async_trait]
pub trait BlockAdapter<T> {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &T,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        prefix_path: &str,
    ) -> Result<Address, AksharaError>;

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> Result<T, AksharaError>;
}

#[async_trait]
pub trait GraphStoreExt {
    async fn get_decrypted_block(
        &self,
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
    ) -> Result<Vec<u8>, AksharaError>;
}

#[async_trait]
impl<S: GraphStore + ?Sized> GraphStoreExt for S {
    async fn get_decrypted_block(
        &self,
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
    ) -> Result<Vec<u8>, AksharaError> {
        let block_id = BlockId::try_from(*address)?;
        let block = self.get_block(&block_id).await?.ok_or_else(|| {
            AksharaError::Store(akshara_aadhaara::StoreError::NotFound(format!(
                "Block {} not found in store",
                block_id
            )))
        })?;
        let plaintext = block.decrypt(graph_id, key)?;
        Ok(plaintext)
    }
}

pub struct StandaloneBlockAdapter;

#[async_trait]
impl<T> BlockAdapter<T> for StandaloneBlockAdapter
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    async fn serialize<S: GraphStore + ?Sized>(
        value: &T,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> Result<Address, AksharaError> {
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
    ) -> Result<T, AksharaError> {
        let plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let value = akshara_aadhaara::from_canonical_bytes(&plaintext)?;
        Ok(value)
    }
}

pub struct TextDocumentAdapter;

#[async_trait]
impl BlockAdapter<String> for TextDocumentAdapter {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &String,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> Result<Address, AksharaError> {
        let sentences = split_sentences(value);
        let keys = generate_fractional_keys(sentences.len());

        let mut index_map = BTreeMap::new();

        for (i, sentence) in sentences.into_iter().enumerate() {
            let plaintext = akshara_aadhaara::to_canonical_bytes(&sentence)?;
            let block = Block::new(
                *graph_id,
                plaintext,
                BlockType::AksharaDataV1,
                vec![],
                key,
                signer,
            )?;
            store.put_block(&block).await?;
            index_map.insert(keys[i].clone(), Address::from(block.id()));
        }

        let index_plaintext = akshara_aadhaara::to_canonical_bytes(&index_map)?;
        let index_block = Block::new(
            *graph_id,
            index_plaintext,
            BlockType::AksharaIndexV1,
            vec![],
            key,
            signer,
        )?;
        store.put_block(&index_block).await?;

        Ok(Address::from(index_block.id()))
    }

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> Result<String, AksharaError> {
        let index_plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let index_map: BTreeMap<String, Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;

        let mut assembled = String::new();

        for (_k, addr) in index_map {
            let plaintext = store.get_decrypted_block(&addr, graph_id, key).await?;
            let sentence: String = akshara_aadhaara::from_canonical_bytes(&plaintext)?;
            assembled.push_str(&sentence);
        }

        Ok(assembled)
    }
}

fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        current.push(c);
        if c == '.' || c == '?' || c == '!' {
            let mut is_end = true;
            if i + 1 < chars.len() {
                is_end = chars[i + 1].is_whitespace();
            }
            if is_end {
                i += 1;
                while i < chars.len() && chars[i].is_whitespace() {
                    current.push(chars[i]);
                    i += 1;
                }
                sentences.push(current.clone());
                current.clear();
                continue;
            }
        }
        i += 1;
    }
    if !current.is_empty() {
        sentences.push(current);
    }
    sentences
}

fn generate_fractional_keys(count: usize) -> Vec<String> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        keys.push(format!("a{:04}", i));
    }
    keys
}

pub struct ChunkedBlockAdapter;

static CHUNK_SIZE: AtomicUsize = AtomicUsize::new(1024 * 1024); // Default 1MB chunks

impl ChunkedBlockAdapter {
    pub fn set_chunk_size(size: usize) {
        CHUNK_SIZE.store(size, Ordering::Relaxed);
    }

    pub fn get_chunk_size() -> usize {
        CHUNK_SIZE.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl BlockAdapter<Vec<u8>> for ChunkedBlockAdapter {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &Vec<u8>,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> Result<Address, AksharaError> {
        let chunk_size = Self::get_chunk_size();
        let mut chunk_addresses = Vec::new();
        for chunk in value.chunks(chunk_size) {
            let plaintext = akshara_aadhaara::to_canonical_bytes(&chunk.to_vec())?;
            let block = Block::new(
                *graph_id,
                plaintext,
                BlockType::AksharaDataV1,
                vec![],
                key,
                signer,
            )?;
            store.put_block(&block).await?;
            chunk_addresses.push(Address::from(block.id()));
        }

        let index_plaintext = akshara_aadhaara::to_canonical_bytes(&chunk_addresses)?;
        let index_block = Block::new(
            *graph_id,
            index_plaintext,
            BlockType::AksharaIndexV1,
            vec![],
            key,
            signer,
        )?;
        store.put_block(&index_block).await?;

        Ok(Address::from(index_block.id()))
    }

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> Result<Vec<u8>, AksharaError> {
        let index_plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let chunk_addresses: Vec<Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;

        let mut assembled = Vec::new();

        for addr in chunk_addresses {
            let plaintext = store.get_decrypted_block(&addr, graph_id, key).await?;
            let chunk_data: Vec<u8> = akshara_aadhaara::from_canonical_bytes(&plaintext)?;
            assembled.extend_from_slice(&chunk_data);
        }

        Ok(assembled)
    }
}

pub struct CollectionBlockAdapter;

#[async_trait]
impl<T> BlockAdapter<Vec<T>> for CollectionBlockAdapter
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    async fn serialize<S: GraphStore + ?Sized>(
        value: &Vec<T>,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> Result<Address, AksharaError> {
        let keys = generate_fractional_keys(value.len());
        let mut index_map = BTreeMap::new();

        for (i, item) in value.iter().enumerate() {
            let plaintext = akshara_aadhaara::to_canonical_bytes(item)?;
            let block = Block::new(
                *graph_id,
                plaintext,
                BlockType::AksharaDataV1,
                vec![],
                key,
                signer,
            )?;
            store.put_block(&block).await?;
            index_map.insert(keys[i].clone(), Address::from(block.id()));
        }

        let index_plaintext = akshara_aadhaara::to_canonical_bytes(&index_map)?;
        let index_block = Block::new(
            *graph_id,
            index_plaintext,
            BlockType::AksharaIndexV1,
            vec![],
            key,
            signer,
        )?;
        store.put_block(&index_block).await?;

        Ok(Address::from(index_block.id()))
    }

    async fn deserialize<S: GraphStore + ?Sized>(
        address: &Address,
        graph_id: &GraphId,
        key: &GraphKey,
        store: &S,
    ) -> Result<Vec<T>, AksharaError> {
        let index_plaintext = store.get_decrypted_block(address, graph_id, key).await?;
        let index_map: BTreeMap<String, Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;

        let mut items = Vec::with_capacity(index_map.len());

        for (_k, addr) in index_map {
            let plaintext = store.get_decrypted_block(&addr, graph_id, key).await?;
            let item: T = akshara_aadhaara::from_canonical_bytes(&plaintext)?;
            items.push(item);
        }

        Ok(items)
    }
}
