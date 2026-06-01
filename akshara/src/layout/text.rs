use crate::error::{Error, Result};
use crate::layout::{BlockLayout, GraphStoreExt};
use akshara_aadhaara::{
    Address, AksharaError, Block, BlockType, GraphId, GraphKey, GraphStore, SecretIdentity,
};
use async_trait::async_trait;
use std::collections::BTreeMap;

pub struct TextLayout;

#[async_trait]
impl BlockLayout<String> for TextLayout {
    async fn serialize<S: GraphStore + ?Sized>(
        value: &String,
        graph_id: &GraphId,
        key: &GraphKey,
        signer: &SecretIdentity,
        store: &S,
        _prefix_path: &str,
    ) -> std::result::Result<Address, AksharaError> {
        let (index_block, data_blocks) =
            decompose(value, graph_id, key, signer).map_err(|e| match e {
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
    ) -> std::result::Result<String, AksharaError> {
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

/// Decomposes unstructured text into sentence blocks and a root index block.
pub fn decompose(
    text: &str,
    graph_id: &GraphId,
    key: &GraphKey,
    signer: &SecretIdentity,
) -> Result<(Block, Vec<Block>)> {
    let sentences = split_sentences(text);
    let keys = super::collection::generate_fractional_keys(sentences.len());
    let mut index_map = BTreeMap::new();
    let mut data_blocks = Vec::new();

    for (i, sentence) in sentences.into_iter().enumerate() {
        let plaintext = akshara_aadhaara::to_canonical_bytes(&sentence)
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

/// Splits unstructured text into sentences.
pub fn split_sentences(text: &str) -> Vec<String> {
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
