pub mod mapping;
pub mod service;

pub mod sovereign_relay {
    pub mod v1 {
        tonic::include_proto!("sovereign.relay.v1");
    }
}
