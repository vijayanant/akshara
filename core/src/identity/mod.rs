use crate::crypto::{
    EncryptionPublicKey, EncryptionSecretKey, Signature, SigningPublicKey, SigningSecretKey,
};
use crate::error::SovereignError;
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    signing_key: SigningPublicKey,
    encryption_key: EncryptionPublicKey,
}

impl Identity {
    pub fn new(signing_key: SigningPublicKey, encryption_key: EncryptionPublicKey) -> Self {
        Self {
            signing_key,
            encryption_key,
        }
    }

    pub fn signing_key(&self) -> &SigningPublicKey {
        &self.signing_key
    }

    pub fn encryption_key(&self) -> &EncryptionPublicKey {
        &self.encryption_key
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verify(message, signature).is_ok()
    }
}

pub struct SecretIdentity {
    signing_key: SigningSecretKey,
    encryption_key: EncryptionSecretKey,
    public: Identity,
}

impl SecretIdentity {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let signing_key = SigningKey::generate(rng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, SovereignError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| SovereignError::MnemonicError(e.to_string()))?;
        let seed = mnemonic.to_seed("");

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[0..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Self::from_signing_key(signing_key))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let signing_public = signing_key.verifying_key();

        let encryption_secret = StaticSecret::from(signing_key.to_bytes());
        let encryption_public = XPublicKey::from(&encryption_secret);

        let public_id = Identity::new(
            SigningPublicKey::new(signing_public.to_bytes()),
            EncryptionPublicKey::new(*encryption_public.as_bytes()),
        );

        Self {
            signing_key: SigningSecretKey::new(signing_key.to_bytes()),
            encryption_key: EncryptionSecretKey::new(encryption_secret.to_bytes()),
            public: public_id,
        }
    }

    pub fn signing_key(&self) -> &SigningSecretKey {
        &self.signing_key
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        // Regenerate key from secure bytes
        let key = SigningKey::from_bytes(self.signing_key.as_bytes());
        let sig = key.sign(message);
        Signature::new(sig.to_vec())
    }

    pub fn public(&self) -> &Identity {
        &self.public
    }

    pub fn encryption_key(&self) -> &EncryptionSecretKey {
        &self.encryption_key
    }
}
