use crate::base::address::{Address, BlockId};
use crate::base::crypto::{GraphKey, SovereignSigner};
use crate::base::error::SovereignError;
use crate::graph::{Block, BlockType};
use crate::state::store::GraphStore;
use std::collections::BTreeMap;

/// `IndexBuilder` is a primitive for constructing nested Merkle-Index trees.
///
/// It allows developers to specify a flat list of paths and their associated CIDs,
/// then automatically handles the recursive bottom-up hashing and persistence
/// required to form a valid Merkle-DAG.
pub struct IndexBuilder {
    tree: BTreeMap<String, IndexNode>,
}

enum IndexNode {
    Leaf(Address),
    Branch(BTreeMap<String, IndexNode>),
}

impl IndexBuilder {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
        }
    }

    /// Inserts an address into the virtual tree at the specified path.
    pub fn insert(&mut self, path: &str, address: Address) -> Result<(), SovereignError> {
        let segments: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if segments.is_empty() {
            return Err(SovereignError::InternalError(
                "Path cannot be empty".to_string(),
            ));
        }

        let mut current_map = &mut self.tree;

        for (i, segment) in segments.iter().enumerate() {
            let is_last = i == segments.len() - 1;

            if is_last {
                current_map.insert(segment.to_string(), IndexNode::Leaf(address));
            } else {
                let entry = current_map
                    .entry(segment.to_string())
                    .or_insert_with(|| IndexNode::Branch(BTreeMap::new()));

                match entry {
                    IndexNode::Branch(next_map) => current_map = next_map,
                    IndexNode::Leaf(_) => {
                        return Err(SovereignError::InternalError(format!(
                            "Path conflict at segment: {}",
                            segment
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Recursively builds and persists the Merkle-Index blocks to the store.
    ///
    /// Returns the BlockId of the Root Index.
    pub async fn build<S: GraphStore + ?Sized>(
        &self,
        store: &mut S,
        signer: &impl SovereignSigner,
        key: &GraphKey,
    ) -> Result<BlockId, SovereignError> {
        self.persist_node(&self.tree, store, signer, key).await
    }

    async fn persist_node<S: GraphStore + ?Sized>(
        &self,
        map: &BTreeMap<String, IndexNode>,
        store: &mut S,
        signer: &impl SovereignSigner,
        key: &GraphKey,
    ) -> Result<BlockId, SovereignError> {
        let mut final_map = BTreeMap::new();

        for (name, node) in map {
            match node {
                IndexNode::Leaf(addr) => {
                    final_map.insert(name.clone(), *addr);
                }
                IndexNode::Branch(sub_map) => {
                    let child_id = Box::pin(self.persist_node(sub_map, store, signer, key)).await?;
                    final_map.insert(name.clone(), Address::from(child_id));
                }
            }
        }

        let plaintext = crate::base::encoding::to_canonical_bytes(&final_map)?;

        let index_block = Block::new(plaintext, BlockType::AksharaIndexV1, vec![], key, signer)?;

        store.put_block(&index_block).await?;
        Ok(index_block.id())
    }
}

impl Default for IndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}
