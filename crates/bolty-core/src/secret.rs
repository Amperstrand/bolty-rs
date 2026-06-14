use core::fmt;

use zeroize::Zeroize;

/// A 16-byte AES key held only in RAM.
/// Never serialized, never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct AesKey([u8; 16]);

impl AesKey {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, SecretError> {
        crate::util::decode_hex(s)
            .ok_or(SecretError::InvalidHex)
            .map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn zeroed() -> Self {
        Self([0u8; 16])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl fmt::Debug for AesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AesKey([REDACTED])")
    }
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    InvalidHex,
    InvalidLength,
}

/// Set of 5 card keys (K0–K4). Zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct CardKeys {
    pub k0: AesKey,
    pub k1: AesKey,
    pub k2: AesKey,
    pub k3: AesKey,
    pub k4: AesKey,
}

impl CardKeys {
    pub fn zeroed() -> Self {
        Self {
            k0: AesKey::zeroed(),
            k1: AesKey::zeroed(),
            k2: AesKey::zeroed(),
            k3: AesKey::zeroed(),
            k4: AesKey::zeroed(),
        }
    }
}

impl fmt::Debug for CardKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CardKeys([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{AesKey, CardKeys, SecretError};

    // ── AesKey::new / as_bytes ─────────────────────────────────────

    #[test]
    fn new_preserves_bytes() {
        let raw = [0x42u8; 16];
        let key = AesKey::new(raw);
        assert_eq!(key.as_bytes(), &raw);
    }

    // ── AesKey::from_hex ───────────────────────────────────────────

    #[test]
    fn from_hex_valid() {
        let key = AesKey::from_hex("00000000000000000000000000000001").unwrap();
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(key.as_bytes(), &expected);
    }

    #[test]
    fn from_hex_valid_all_zeros() {
        let key = AesKey::from_hex("00000000000000000000000000000000").unwrap();
        assert!(key.is_zero());
    }

    #[test]
    fn from_hex_uppercase() {
        let key = AesKey::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        assert_eq!(key.as_bytes(), &[0xFFu8; 16]);
    }

    #[test]
    fn from_hex_wrong_length() {
        assert_eq!(AesKey::from_hex("0001"), Err(SecretError::InvalidHex));
    }

    #[test]
    fn from_hex_invalid_chars() {
        assert_eq!(AesKey::from_hex("GG00000000000000000000000000000X"), Err(SecretError::InvalidHex));
    }

    #[test]
    fn from_hex_empty() {
        assert_eq!(AesKey::from_hex(""), Err(SecretError::InvalidHex));
    }

    // ── AesKey::zeroed / is_zero ───────────────────────────────────

    #[test]
    fn zeroed_is_zero() {
        let key = AesKey::zeroed();
        assert!(key.is_zero());
    }

    #[test]
    fn nonzero_is_not_zero() {
        let mut raw = [0u8; 16];
        raw[0] = 1;
        let key = AesKey::new(raw);
        assert!(!key.is_zero());
    }

    #[test]
    fn partial_zeros_not_zero() {
        let mut raw = [0u8; 16];
        raw[15] = 0x42;
        let key = AesKey::new(raw);
        assert!(!key.is_zero());
    }

    // ── Debug redaction ────────────────────────────────────────────

    #[test]
    fn aeskey_debug_redacted() {
        let key = AesKey::new([0xDE; 16]);
        assert_eq!(format!("{:?}", key), "AesKey([REDACTED])");
    }

    #[test]
    fn cardkeys_debug_redacted() {
        let keys = CardKeys::zeroed();
        assert_eq!(format!("{:?}", keys), "CardKeys([REDACTED])");
    }

    // ── Clone / PartialEq ──────────────────────────────────────────

    #[test]
    fn clone_equals_original() {
        let key = AesKey::new([0xAB; 16]);
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn different_keys_not_equal() {
        let a = AesKey::new([0; 16]);
        let b = AesKey::new([1; 16]);
        assert_ne!(a, b);
    }

    // ── CardKeys::zeroed ───────────────────────────────────────────

    #[test]
    fn cardkeys_zeroed_all_zero() {
        let keys = CardKeys::zeroed();
        assert!(keys.k0.is_zero());
        assert!(keys.k1.is_zero());
        assert!(keys.k2.is_zero());
        assert!(keys.k3.is_zero());
        assert!(keys.k4.is_zero());
    }
}

