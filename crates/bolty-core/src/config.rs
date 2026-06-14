use heapless::String;

use crate::{
    constants::{KEY_VERSION_BLANK, KEY_VERSION_PROVISIONED, NUM_KEYS, UID_LEN},
    secret::{AesKey, CardKeys},
};

pub type UrlString = String<256>;
pub type LnurlString = UrlString;
pub type IssuerNameString = String<64>;
pub type MessageString = String<256>;
pub type ErrorString = String<64>;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolty_config_default_all_none() {
        let config = BoltyConfig::default();
        assert!(config.lnurl.is_none());
        assert!(config.issuer_name.is_none());
        assert!(config.pending_keys.is_none());
        assert!(config.pending_issuer.is_none());
        assert!(config.rest_read_token.is_none());
        assert!(config.rest_write_token.is_none());
    }

    #[test]
    fn issuer_config_default_values() {
        let config = IssuerConfig::default();
        assert!(config.name.is_none());
        assert!(config.issuer_key.is_zero());
        assert_eq!(config.derivation_version, u32::from(KEY_VERSION_PROVISIONED));
        assert_eq!(config.key_version, KEY_VERSION_PROVISIONED);
    }

    #[test]
    fn issuer_config_with_key() {
        let key = AesKey::new([0xAB; 16]);
        let config = IssuerConfig {
            issuer_key: key,
            derivation_version: 2,
            key_version: 0x42,
            ..IssuerConfig::default()
        };
        assert_eq!(config.derivation_version, 2);
        assert_eq!(config.key_version, 0x42);
        assert!(!config.issuer_key.is_zero());
    }

    #[test]
    fn card_config_default_values() {
        let config = CardConfig::default();
        assert_eq!(config.uid, [0u8; UID_LEN]);
        assert_eq!(config.key_versions, [KEY_VERSION_BLANK; NUM_KEYS]);
    }

    #[test]
    fn card_config_uid_length() {
        assert_eq!(UID_LEN, 7);
        let config = CardConfig::default();
        assert_eq!(config.uid.len(), 7);
    }

    #[test]
    fn card_config_key_versions_count() {
        assert_eq!(NUM_KEYS, 5);
        let config = CardConfig::default();
        assert_eq!(config.key_versions.len(), 5);
    }

    #[test]
    fn bolty_config_clone_eq() {
        let a = BoltyConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn issuer_config_clone_eq() {
        let a = IssuerConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn card_config_copy_eq() {
        let a = CardConfig::default();
        let b = a;
        assert_eq!(a, b);
    }
}
