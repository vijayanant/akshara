pub mod discovery;
pub mod error;
pub mod mapping;
pub mod sync;

pub mod sovereign_relay {
    pub mod v1 {
        tonic::include_proto!("sovereign.relay.v1");
    }
}
