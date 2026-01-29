use crate::sovereign_relay::v1 as proto;
use sovereign_core::crypto::{
    BlockContent, EncryptionPublicKey, Lockbox, Signature as CoreSignature, SigningPublicKey,
};
use sovereign_core::graph::{Block, BlockId, GraphId, Manifest, ManifestId};
use std::convert::TryFrom;
use tonic::Status;
use uuid::Uuid;

// --- ID Conversions ---

impl From<BlockId> for proto::BlockId {
    fn from(id: BlockId) -> Self {
        proto::BlockId { val: id.0.to_vec() }
    }
}

impl TryFrom<proto::BlockId> for BlockId {
    type Error = StatusWrapper;
    fn try_from(p: proto::BlockId) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = p
            .val
            .try_into()
            .map_err(|_| StatusWrapper::invalid("Invalid BlockId length"))?;
        Ok(BlockId(bytes))
    }
}

impl From<ManifestId> for proto::ManifestId {
    fn from(id: ManifestId) -> Self {
        proto::ManifestId { val: id.0.to_vec() }
    }
}

impl TryFrom<proto::ManifestId> for ManifestId {
    type Error = StatusWrapper;
    fn try_from(p: proto::ManifestId) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = p
            .val
            .try_into()
            .map_err(|_| StatusWrapper::invalid("Invalid ManifestId length"))?;
        Ok(ManifestId(bytes))
    }
}

// --- Crypto Conversions ---

impl From<SigningPublicKey> for proto::PublicKey {
    fn from(k: SigningPublicKey) -> Self {
        proto::PublicKey {
            val: k.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<proto::PublicKey> for SigningPublicKey {
    type Error = StatusWrapper;
    fn try_from(p: proto::PublicKey) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = p
            .val
            .try_into()
            .map_err(|_| StatusWrapper::invalid("Invalid PublicKey length"))?;
        Ok(SigningPublicKey::new(bytes))
    }
}

impl From<EncryptionPublicKey> for proto::PublicKey {
    fn from(k: EncryptionPublicKey) -> Self {
        proto::PublicKey {
            val: k.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<proto::PublicKey> for EncryptionPublicKey {
    type Error = StatusWrapper;
    fn try_from(p: proto::PublicKey) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = p
            .val
            .try_into()
            .map_err(|_| StatusWrapper::invalid("Invalid PublicKey length"))?;
        Ok(EncryptionPublicKey::new(bytes))
    }
}

impl From<CoreSignature> for proto::Signature {
    fn from(s: CoreSignature) -> Self {
        proto::Signature {
            val: s.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<proto::Signature> for CoreSignature {
    type Error = StatusWrapper;
    fn try_from(p: proto::Signature) -> Result<Self, Self::Error> {
        Ok(CoreSignature::new(p.val))
    }
}

impl From<BlockContent> for proto::BlockContent {
    fn from(c: BlockContent) -> Self {
        proto::BlockContent {
            ciphertext: c.as_bytes().to_vec(),
            nonce: c.nonce().to_vec(),
        }
    }
}

impl TryFrom<proto::BlockContent> for BlockContent {
    type Error = StatusWrapper;
    fn try_from(p: proto::BlockContent) -> Result<Self, Self::Error> {
        let nonce: [u8; 12] = p
            .nonce
            .try_into()
            .map_err(|_| StatusWrapper::invalid("Invalid Nonce length"))?;
        Ok(BlockContent::from_raw_parts(p.ciphertext, nonce))
    }
}

impl From<Lockbox> for proto::Lockbox {
    fn from(l: Lockbox) -> Self {
        proto::Lockbox {
            ephemeral_public_key: Some(l.ephemeral_public_key.into()),
            content: Some(l.content.into()),
        }
    }
}

impl TryFrom<proto::Lockbox> for Lockbox {
    type Error = StatusWrapper;
    fn try_from(p: proto::Lockbox) -> Result<Self, Self::Error> {
        Ok(Lockbox::from_raw_parts(
            p.ephemeral_public_key
                .ok_or_else(|| Status::invalid_argument("Missing Ephemeral Public Key"))?
                .try_into()?,
            p.content
                .ok_or_else(|| Status::invalid_argument("Missing Content"))?
                .try_into()?,
        ))
    }
}

// --- Composite Conversions ---

impl From<Block> for proto::Block {
    fn from(b: Block) -> Self {
        proto::Block {
            id: Some(b.id().into()),
            author_key: Some(b.author().clone().into()),
            signature: Some(b.signature().clone().into()),
            content: Some(b.content().clone().into()),
            rank: b.rank().to_string(),
            block_type: b.block_type().to_string(),
            parents: b.parents().iter().map(|p| (*p).into()).collect(),
        }
    }
}

impl TryFrom<proto::Block> for Block {
    type Error = StatusWrapper;
    fn try_from(p: proto::Block) -> Result<Self, Self::Error> {
        Ok(Block::from_raw_parts(
            p.id.ok_or_else(|| Status::invalid_argument("Missing Block ID"))?
                .try_into()?,
            p.author_key
                .ok_or_else(|| Status::invalid_argument("Missing Author Key"))?
                .try_into()?,
            p.signature
                .ok_or_else(|| Status::invalid_argument("Missing Signature"))?
                .try_into()?,
            p.content
                .ok_or_else(|| Status::invalid_argument("Missing Content"))?
                .try_into()?,
            p.rank,
            p.block_type,
            p.parents
                .into_iter()
                .map(|id| id.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl From<Manifest> for proto::Manifest {
    fn from(m: Manifest) -> Self {
        proto::Manifest {
            id: Some(m.id().into()),
            graph_id: m.graph_id().0.to_string(),
            parents: m.parents().iter().map(|p| (*p).into()).collect(),
            active_blocks: m.active_blocks().iter().map(|b| (*b).into()).collect(),
            merkle_root: Some(m.merkle_root().into()),
            author_key: Some(m.author().clone().into()),
            signature: Some(m.signature().clone().into()),
            created_at: m.created_at(),
        }
    }
}

impl TryFrom<proto::Manifest> for Manifest {
    type Error = StatusWrapper;
    fn try_from(p: proto::Manifest) -> Result<Self, Self::Error> {
        let doc_uuid = Uuid::parse_str(&p.graph_id)
            .map_err(|_| Status::invalid_argument("Invalid GraphId format"))?;

        Ok(Manifest::from_raw_parts(
            p.id.ok_or_else(|| Status::invalid_argument("Missing Manifest ID"))?
                .try_into()?,
            GraphId(doc_uuid),
            p.parents
                .into_iter()
                .map(|id| id.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            p.active_blocks
                .into_iter()
                .map(|id| id.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            p.merkle_root
                .ok_or_else(|| Status::invalid_argument("Missing Merkle Root"))?
                .try_into()?,
            p.author_key
                .ok_or_else(|| Status::invalid_argument("Missing Author Key"))?
                .try_into()?,
            p.signature
                .ok_or_else(|| Status::invalid_argument("Missing Signature"))?
                .try_into()?,
            p.created_at,
        ))
    }
}

// --- Error Wrapper ---
pub struct StatusWrapper(pub Status);

impl StatusWrapper {
    fn invalid(msg: &str) -> Self {
        StatusWrapper(Status::invalid_argument(msg))
    }
}

impl From<StatusWrapper> for Status {
    fn from(w: StatusWrapper) -> Self {
        w.0
    }
}

impl From<Status> for StatusWrapper {
    fn from(s: Status) -> Self {
        StatusWrapper(s)
    }
}
