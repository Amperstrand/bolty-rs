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


