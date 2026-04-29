use heapless::String;

use crate::{
    constants::{KEY_VERSION_BLANK, KEY_VERSION_PROVISIONED, NUM_KEYS, UID_LEN},
    secret::{AesKey, CardKeys},
};

pub type UrlString = String<256>;
pub type LnurlString = UrlString;
pub type IssuerNameString = String<64>;
pub type MessageString = String<256>;
pub type WifiSsidString = String<32>;
pub type WifiPasswordString = String<64>;
pub type RestTokenString = String<64>;

/// Runtime config shared by serial/REST/UI orchestration.
///
/// `pending_keys` and `pending_issuer` are RAM-only workflow state and must not
/// be persisted or logged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoltyConfig {
    pub lnurl: Option<LnurlString>,
    pub issuer_name: Option<IssuerNameString>,
    pub pending_keys: Option<CardKeys>,
    pub pending_issuer: Option<AesKey>,
    pub rest_read_token: Option<RestTokenString>,
    pub rest_write_token: Option<RestTokenString>,
}

/// Issuer material required to deterministically derive a card keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    pub name: Option<IssuerNameString>,
    pub issuer_key: AesKey,
    pub derivation_version: u32,
    pub key_version: u8,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            name: None,
            issuer_key: AesKey::zeroed(),
            derivation_version: u32::from(KEY_VERSION_PROVISIONED),
            key_version: KEY_VERSION_PROVISIONED,
        }
    }
}

/// Card-side metadata needed for pure policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardConfig {
    pub uid: [u8; UID_LEN],
    pub key_versions: [u8; NUM_KEYS],
}

impl Default for CardConfig {
    fn default() -> Self {
        Self {
            uid: [0u8; UID_LEN],
            key_versions: [KEY_VERSION_BLANK; NUM_KEYS],
        }
    }
}
