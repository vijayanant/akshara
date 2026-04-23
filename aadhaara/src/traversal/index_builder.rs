use crate::base::address::{Address, BlockId, GraphId};
use crate::base::crypto::{AksharaSigner, GraphKey};
use crate::base::error::AksharaError;
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
    pub fn insert(&mut self, path: &str, address: Address) -> Result<(), AksharaError> {
        let segments = self.normalize_path(path)?;
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
                        return Err(AksharaError::InternalError(format!(
                            "Path conflict at segment: {}",
                            segment
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Removes a path from the virtual tree.
    pub fn remove(&mut self, path: &str) -> Result<(), AksharaError> {
        let segments = self.normalize_path(path)?;
        let mut current_map = &mut self.tree;

        for (i, segment) in segments.iter().enumerate() {
            let is_last = i == segments.len() - 1;

            if is_last {
                current_map.remove(*segment);
                return Ok(());
            } else {
                match current_map.get_mut(*segment) {
                    Some(IndexNode::Branch(next_map)) => current_map = next_map,
                    _ => return Ok(()), // Path doesn't exist; nothing to remove
                }
            }
        }

        Ok(())
    }

    /// Imports an existing Merkle-Index state into the builder.
    ///
    /// This allows for incremental updates by loading the current state
    /// before applying changes.
    pub async fn import_from_root<S: GraphStore + ?Sized>(
        &mut self,
        graph_id: &GraphId,
        root: &BlockId,
        store: &S,
        key: &GraphKey,
    ) -> Result<(), AksharaError> {
        self.tree = self.load_node_recursive(graph_id, root, store, key).await?;
        Ok(())
    }

    async fn load_node_recursive<S: GraphStore + ?Sized>(
        &self,
        graph_id: &GraphId,
        block_id: &BlockId,
        store: &S,
        key: &GraphKey,
    ) -> Result<BTreeMap<String, IndexNode>, AksharaError> {
        let block = store.get_block(block_id).await?.ok_or_else(|| {
            AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                "Index block {}",
                block_id
            )))
        })?;

        let plaintext = block.decrypt(graph_id, key)?;
        let index_map: BTreeMap<String, Address> =
            crate::base::encoding::from_canonical_bytes(&plaintext)?;

        let mut virtual_map = BTreeMap::new();

        for (name, addr) in index_map {
            if addr.codec() == crate::base::address::CODEC_AKSHARA_BLOCK {
                // Determine if this is a sub-index or a data leaf
                // We must check the block type to be sure
                let child_id = BlockId::try_from(addr)?;
                let child_block = store.get_block(&child_id).await?.ok_or_else(|| {
                    AksharaError::Store(crate::base::error::StoreError::NotFound(format!(
                        "Child block {}",
                        child_id
                    )))
                })?;

                if *child_block.block_type() == crate::graph::BlockType::AksharaIndexV1 {
                    let sub_tree =
                        Box::pin(self.load_node_recursive(graph_id, &child_id, store, key)).await?;
                    virtual_map.insert(name, IndexNode::Branch(sub_tree));
                } else {
                    virtual_map.insert(name, IndexNode::Leaf(addr));
                }
            } else {
                virtual_map.insert(name, IndexNode::Leaf(addr));
            }
        }

        Ok(virtual_map)
    }

    fn normalize_path<'a>(&self, path: &'a str) -> Result<Vec<&'a str>, AksharaError> {
        let segments: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if segments.is_empty() {
            return Err(AksharaError::InternalError(
                "Path cannot be empty".to_string(),
            ));
        }
        Ok(segments)
    }

    /// Recursively builds and persists the Merkle-Index blocks to the store.
    ///
    /// Returns the BlockId of the Root Index.
    pub async fn build<S: GraphStore + ?Sized>(
        &self,
        graph_id: GraphId,
        store: &S,
        signer: &impl AksharaSigner,
        key: &GraphKey,
    ) -> Result<BlockId, AksharaError> {
        self.materialize_node(graph_id, &self.tree, store, signer, key)
            .await
    }

    async fn materialize_node<S: GraphStore + ?Sized>(
        &self,
        graph_id: GraphId,
        map: &BTreeMap<String, IndexNode>,
        store: &S,
        signer: &impl AksharaSigner,
        key: &GraphKey,
    ) -> Result<BlockId, AksharaError> {
        let mut final_map = BTreeMap::new();

        for (name, node) in map {
            match node {
                IndexNode::Leaf(addr) => {
                    final_map.insert(name.clone(), *addr);
                }
                IndexNode::Branch(sub_map) => {
                    let child_id =
                        Box::pin(self.materialize_node(graph_id, sub_map, store, signer, key))
                            .await?;
                    final_map.insert(name.clone(), Address::from(child_id));
                }
            }
        }

        let plaintext = crate::base::encoding::to_canonical_bytes(&final_map)?;

        let index_block = Block::new(
            graph_id,
            plaintext,
            BlockType::AksharaIndexV1,
            vec![],
            key,
            signer,
        )?;

        store.put_block(&index_block).await?;
        Ok(index_block.id())
    }
}

impl Default for IndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}
