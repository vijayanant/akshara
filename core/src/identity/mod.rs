use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    signing_key: [u8; 32],
}

impl Identity {
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self { signing_key }
    }

    pub fn signing_key(&self) -> [u8; 32] {
        self.signing_key
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.signing_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(signature_bytes);
        verifying_key.verify(message, &signature).is_ok()
    }
}

pub struct SecretIdentity {
    signing_key: SigningKey,
}

impl SecretIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, String> {
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, phrase).map_err(|e| e.to_string())?;
        let seed = mnemonic.to_seed("");

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[0..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn public(&self) -> Identity {
        Identity::new(self.signing_key.verifying_key().to_bytes())
    }
}
