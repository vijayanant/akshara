#![allow(dead_code)]

/// The purpose index for Akshara Hierarchical Deterministic (HD) wallets (BIP-44).
pub const PURPOSE_AKSHARA: u32 = 44;

/// The registered coin type for Sovereign Systems (BIP-44).
pub const COIN_TYPE_AKSHARA: u32 = 999;

/// The primary account index for Akshara identities.
pub const DEFAULT_ACCOUNT: u32 = 0;

/// Branch 0: Legislator (Management Authority)
/// Used for authorizing and revoking executive credentials.
pub const BRANCH_LEGISLATOR: u32 = 0;

/// Branch 1: Executive (Operational Authority)
/// Used for signing graph manifests.
pub const BRANCH_EXECUTIVE: u32 = 1;

/// Branch 2: Secret (Encryption Authority)
/// Used for deriving symmetric graph keys.
pub const BRANCH_SECRET: u32 = 2;

/// Branch 3: Handshake (Asynchronous Discovery)
/// Used for deriving Pre-Key bundles.
pub const BRANCH_HANDSHAKE: u32 = 3;

/// Branch 4: Internal Vault (Keyring Secret)
/// Used for shared access across authorized devices.
pub const BRANCH_KEYRING: u32 = 4;

/// Formats a full BIP-32 path for a specific branch and index.
pub fn format_akshara_path(branch: u32, index: u32) -> String {
    format!(
        "m/{}'/{}'/0'/{}'/{}'",
        PURPOSE_AKSHARA, COIN_TYPE_AKSHARA, branch, index
    )
}
