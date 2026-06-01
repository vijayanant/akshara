use async_trait::async_trait;
use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

use akshara_aadhaara::{
    Address, BlockId, GraphId, GraphKey, GraphStore, SecretIdentity, Block, BlockType, AksharaError
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
        let block_id = BlockId::try_from(*address)?;
        let block = store.get_block(&block_id).await?.ok_or_else(|| {
            AksharaError::Store(akshara_aadhaara::base::error::StoreError::NotFound(format!(
                "Block {} not found in store",
                block_id
            )))
        })?;
        let plaintext = block.decrypt(graph_id, key)?;
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
        let root_id = BlockId::try_from(*address)?;
        let index_block = store.get_block(&root_id).await?.ok_or_else(|| {
            AksharaError::Store(akshara_aadhaara::base::error::StoreError::NotFound(format!(
                "Index block {} not found",
                root_id
            )))
        })?;
        
        let index_plaintext = index_block.decrypt(graph_id, key)?;
        let index_map: BTreeMap<String, Address> =
            akshara_aadhaara::from_canonical_bytes(&index_plaintext)?;
            
        let mut assembled = String::new();
        
        for (_k, addr) in index_map {
            let child_id = BlockId::try_from(addr)?;
            let child_block = store.get_block(&child_id).await?.ok_or_else(|| {
                AksharaError::Store(akshara_aadhaara::base::error::StoreError::NotFound(format!(
                    "Child block {} not found",
                    child_id
                )))
            })?;
            let plaintext = child_block.decrypt(graph_id, key)?;
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
                if chars[i + 1].is_whitespace() {
                    is_end = true;
                } else {
                    is_end = false;
                }
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
