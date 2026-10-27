// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::types::KeyNumber;

use super::error::{FileSettingsError, NibbleSlot};

/// File type identifier.
///
/// NT4H2421Gx §10.7.2, Table 73.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// `00h` — only file type currently defined for NTAG 424 DNA.
    StandardData,
}

impl FileType {
    pub(super) fn from_byte(b: u8) -> Result<Self, FileSettingsError> {
        match b {
            0x00 => Ok(Self::StandardData),
            v => Err(FileSettingsError::UnknownFileType(v)),
        }
    }
}

/// Communication mode for a file (how data is protected on the wire).
///
/// NT4H2421Gx §8.2.3, Table 22.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommMode {
    /// `0Xb` - message in plaintext.
    Plain,
    /// `01b` - MAC for integrity and authenticity.
    Mac,
    /// `11b` - full protection (encryption + MAC).
    Full,
}

impl CommMode {
    pub(super) fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0b01 => Self::Mac,
            0b11 => Self::Full,
            _ => Self::Plain,
        }
    }

    pub(super) fn to_bits(self) -> u8 {
        match self {
            Self::Plain => 0b00,
            Self::Mac => 0b01,
            Self::Full => 0b11,
        }
    }
}

/// Access condition for a file permission slot.
///
/// NT4H2421Gx §8.2.3.3, Table 7.
///
/// Used for file-level access rights (Read, Write, ReadWrite, Change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Authentication with the given AppKey is required.
    ///
    /// `0h..4h`
    Key(KeyNumber),
    /// Free access (no authentication).
    ///
    /// `Eh`
    Free,
    /// No access.
    ///
    /// `Fh`
    NoAccess,
}

impl Access {
    const fn from_nibble(n: u8, slot: NibbleSlot) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => {
                return Err(FileSettingsError::InvalidAccessNibble { slot, value: v });
            }
        })
    }

    const fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// Access right controlling who may retrieve the SDM read counter via
/// [`AuthenticatedSession::get_file_counters`](`crate::AuthenticatedSession::get_file_counters`).
///
/// Uses the same nibble encoding as [`Access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrRetAccess {
    Key(KeyNumber),
    Free,
    NoAccess,
}

impl CtrRetAccess {
    pub(super) const fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => {
                return Err(FileSettingsError::InvalidAccessNibble {
                    slot: NibbleSlot::SdmCtrRet,
                    value: v,
                });
            }
        })
    }

    pub(super) const fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// Set of four access conditions for a file.
///
/// Encodes `Read`, `Write`, `ReadWrite`, and `Change` permissions.
///
/// Access is granted if at least one of the specified conditions
/// is satisfied. For example, if `read` is `Key(Key0)` and
/// `read_write` is `Free`, then read access is granted if either
/// Key0 authentication is successful or no authentication is performed at all.
///
/// NT4H2421Gx §8.2.3.3, Table 7. Wire format: 2 bytes little-endian,
/// `(Read << 12) | (Write << 8) | (ReadWrite << 4) | Change`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    /// Read access right.
    pub read: Access,
    /// Write access right.
    pub write: Access,
    /// Read and write access right.
    ///
    /// Equivalent to assigning the same access right to both `read` and `write`.
    /// There is no command that requires both read and write access at the same time.
    pub read_write: Access,
    /// File settings change rights.
    ///
    /// This controls who may change the file settings (e.g. access rights, communication mode),
    /// which also includes changing the access rights themselves.
    pub change: Access,
}

impl AccessRights {
    pub(super) fn from_le_bytes(b: [u8; 2]) -> Result<Self, FileSettingsError> {
        let v = u16::from_le_bytes(b);
        Ok(Self {
            read: Access::from_nibble(((v >> 12) & 0xF) as u8, NibbleSlot::Read)?,
            write: Access::from_nibble(((v >> 8) & 0xF) as u8, NibbleSlot::Write)?,
            read_write: Access::from_nibble(((v >> 4) & 0xF) as u8, NibbleSlot::ReadWrite)?,
            change: Access::from_nibble((v & 0xF) as u8, NibbleSlot::Change)?,
        })
    }

    pub(super) fn to_le_bytes(self) -> [u8; 2] {
        let v = (u16::from(self.read.to_nibble()) << 12)
            | (u16::from(self.write.to_nibble()) << 8)
            | (u16::from(self.read_write.to_nibble()) << 4)
            | u16::from(self.change.to_nibble());
        v.to_le_bytes()
    }
}
