use serde::{Deserialize, Serialize};

pub mod block;
pub use block::Block;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BlockId(pub [u8; 32]);

impl AsRef<[u8]> for BlockId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for BlockId {
    fn from(bytes: [u8; 32]) -> Self {
        BlockId(bytes)
    }
}
