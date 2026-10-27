// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// ISO/IEC 7816-4 elementary files on NTAG 424 DNA.
///
/// These files are accessible via `ISOReadBinary` / `ISOUpdateBinary`.
///
/// Each variant carries the short ISO FileID (`SFID`, 5 bits) assigned by NXP
/// in NT4H2421Gx §8.2.2 Table 69. The corresponding 16-bit File Identifiers
/// are `E103h` (CC), `E104h` (NDEF), `E105h` (Proprietary).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum File {
    /// Capability Container file - SFID `01h`, File ID `E103h`, 32 bytes.
    CapabilityContainer,
    /// NDEF file - SFID `02h`, File ID `E104h`, default 256 bytes.
    Ndef,
    /// Proprietary file - SFID `03h`, File ID `E105h`, default 128 bytes.
    Proprietary,
}

impl File {
    /// Return the short ISO FileID.
    ///
    /// This is the `01h`–`03h` value used in `ISOReadBinary` /
    /// `ISOUpdateBinary` P1 encoding (ISO/IEC 7816-4 §5.1.1.1).
    pub fn short_file_id(self) -> u8 {
        match self {
            Self::CapabilityContainer => 0x01,
            Self::Ndef => 0x02,
            Self::Proprietary => 0x03,
        }
    }

    /// Return the 16-bit ISO File Identifier.
    ///
    /// This is the `E103h`–`E105h` value used in `ISOSelectFile`
    /// (NT4H2421Gx §8.2.2 Table 69).
    pub fn file_id(self) -> u16 {
        match self {
            Self::CapabilityContainer => 0xE103,
            Self::Ndef => 0xE104,
            Self::Proprietary => 0xE105,
        }
    }

    /// Return the factory file size in bytes.
    ///
    /// NT4H2421Gx §8.2.3: CC = 32 B, NDEF = 256 B, Proprietary = 128 B.
    pub fn size(self) -> u32 {
        match self {
            Self::CapabilityContainer => 32,
            Self::Ndef => 256,
            Self::Proprietary => 128,
        }
    }

    /// Return the native DESFire file number.
    ///
    /// This is the `01h`–`03h` value used in the `CmdHeader` of native
    /// file commands such as `ReadData` (NT4H2421Gx §8.2.1, §10.8.1
    /// Table 78). The NTAG 424 DNA chip exposes exactly three files and
    /// assigns them the same numeric values as their ISO short FileIDs,
    /// but the two are conceptually distinct.
    pub fn file_no(self) -> u8 {
        match self {
            Self::CapabilityContainer => 0x01,
            Self::Ndef => 0x02,
            Self::Proprietary => 0x03,
        }
    }
}
