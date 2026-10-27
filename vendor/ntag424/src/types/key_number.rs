// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// Supported application key numbers for NTAG 424 DNA.
///
/// NTAG 424 DNA exposes five application keys, `0h` to `4h`; key `0` is the
/// Application Master Key.
///
/// All keys should be overwritten even if not used.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyNumber {
    /// Application Master Key.
    Key0,
    Key1,
    Key2,
    Key3,
    Key4,
}

impl KeyNumber {
    /// Encode this key number for the wire.
    ///
    /// The high two bits stay zero and the low nibble carries the key
    /// index (§10.4.1).
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Key0 => 0x00,
            Self::Key1 => 0x01,
            Self::Key2 => 0x02,
            Self::Key3 => 0x03,
            Self::Key4 => 0x04,
        }
    }
}

/// Application key numbers excluding the Application Master Key (`Key0`).
///
/// Used by APIs where targeting `Key0` would change the semantics of the
/// command (e.g. `ChangeKey` Case 1 vs Case 2, AN12196 §5.16); making the
/// distinction at the type level prevents accidental misuse and lets the
/// master-key path expose a different signature.
///
/// **Practical rule:** pass `NonMasterKeyNumber` to [`AuthenticatedSession::change_key`];
/// the compiler rejects `Key0` there at compile time.  To rotate the master
/// key itself, call [`AuthenticatedSession::change_master_key`] instead.
///
/// [`AuthenticatedSession::change_key`]: crate::AuthenticatedSession::change_key
/// [`AuthenticatedSession::change_master_key`]: crate::AuthenticatedSession::change_master_key
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NonMasterKeyNumber {
    Key1,
    Key2,
    Key3,
    Key4,
}

impl NonMasterKeyNumber {
    /// Encode as the `KeyNo` byte sent on the wire.
    pub fn as_byte(self) -> u8 {
        KeyNumber::from(self).as_byte()
    }
}

impl From<NonMasterKeyNumber> for KeyNumber {
    fn from(k: NonMasterKeyNumber) -> Self {
        match k {
            NonMasterKeyNumber::Key1 => KeyNumber::Key1,
            NonMasterKeyNumber::Key2 => KeyNumber::Key2,
            NonMasterKeyNumber::Key3 => KeyNumber::Key3,
            NonMasterKeyNumber::Key4 => KeyNumber::Key4,
        }
    }
}
