// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// UID observed pre-authentication.
///
/// Randomized tags return a 4-byte single-size UID (leading byte
/// `0x08` per ISO/IEC 14443-3) - *not* the
/// permanent UID, which on NTAG 424 DNA is only accessible through
/// `GetCardUID` (INS `51`) after authentication. Normal tags return the
/// permanent 7-byte double-size UID.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Uid {
    Fixed([u8; 7]),
    // TODO: is the leading byte 0x08 always?
    //       can the fixed UIDs also have a leading 0x08?
    Random([u8; 4]),
}

impl Uid {
    /// Return the permanent UID if the tag is not in random-UID mode.
    pub fn as_fixed(&self) -> Option<&[u8; 7]> {
        match self {
            Self::Fixed(bytes) => Some(bytes),
            Self::Random(_) => None,
        }
    }

    pub fn is_random(&self) -> bool {
        matches!(self, Self::Random(_))
    }
}

impl AsRef<[u8]> for Uid {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Fixed(bytes) => bytes.as_ref(),
            Self::Random(bytes) => bytes.as_ref(),
        }
    }
}
