use crate::crypto::{
    EncryptionPublicKey, EncryptionSecretKey, Signature, SigningPublicKey, SigningSecretKey,
    SovereignSigner,
};
use crate::error::SovereignError;
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
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
    /// Generates a fresh random identity using the provided CSPRNG.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let signing_key = SigningKey::generate(rng);
        Self::from_signing_key(signing_key)
    }

    /// Generates a new valid 12-word BIP-39 mnemonic phrase.
    pub fn generate_mnemonic() -> String {
        let mut entropy = [0u8; 16]; // 16 bytes = 128 bits = 12 words
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");
        mnemonic.to_string()
    }

    /// Derives an identity from a BIP-39 mnemonic using the SLIP-0010 standard.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, SovereignError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| SovereignError::MnemonicError(e.to_string()))?;

        let seed = mnemonic.to_seed(passphrase);

        // SLIP-0010 Master Node Derivation
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;
        hmac.update(&seed);
        let output = hmac.finalize().into_bytes();

        let mut master_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        master_key.copy_from_slice(&output[0..32]);
        chain_code.copy_from_slice(&output[32..64]);

        // Path: m / 44' / 999' / 0' / 0' / 0'
        let path: [u32; 5] = [
            44 + 0x8000_0000,
            999 + 0x8000_0000,
            0x8000_0000,
            0x8000_0000,
            0x8000_0000,
        ];

        let mut current_key = master_key;
        let mut current_chain = chain_code;

        for index in path {
            let mut hmac = Hmac::<Sha512>::new_from_slice(&current_chain)
                .map_err(|e| SovereignError::InternalError(e.to_string()))?;
            hmac.update(&[0x00]); // Hardened derivation prefix
            hmac.update(&current_key);
            hmac.update(&index.to_be_bytes());
            let output = hmac.finalize().into_bytes();

            current_key.copy_from_slice(&output[0..32]);
            current_chain.copy_from_slice(&output[32..64]);
        }

        let signing_key = SigningKey::from_bytes(&current_key);
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

    pub fn public(&self) -> &Identity {
        &self.public
    }

    pub fn encryption_key(&self) -> &EncryptionSecretKey {
        &self.encryption_key
    }
}

impl SovereignSigner for SecretIdentity {
    fn sign(&self, message: &[u8]) -> Signature {
        // Regenerate key from secure bytes to minimize exposure time
        let key = SigningKey::from_bytes(self.signing_key.as_bytes());
        let sig = key.sign(message);
        Signature::new(sig.to_vec())
    }

    fn public_key(&self) -> SigningPublicKey {
        self.public.signing_key().clone()
    }
}
