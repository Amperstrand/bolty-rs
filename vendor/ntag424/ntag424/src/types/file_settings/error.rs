// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use core::fmt;

use thiserror::Error;

/// Identifies which nibble slot in the wire encoding failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleSlot {
    Read,
    Write,
    ReadWrite,
    Change,
    SdmMetaRead,
    SdmFileRead,
    SdmCtrRet,
}

impl fmt::Display for NibbleSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::ReadWrite => write!(f, "ReadWrite"),
            Self::Change => write!(f, "Change"),
            Self::SdmMetaRead => write!(f, "SDMMetaRead"),
            Self::SdmFileRead => write!(f, "SDMFileRead"),
            Self::SdmCtrRet => write!(f, "SDMCtrRet"),
        }
    }
}

/// Describes which pair of SDM placeholder regions overlapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapKind {
    UidAndRCtr,
    UidAndTamper,
    RCtrAndTamper,
    UidAndMac,
    RCtrAndMac,
    TamperAndMac,
    EncAndUid,
    EncAndRCtr,
    TamperInCiphertextHalf,
    PiccAndTamper,
    PiccAndMac,
    PiccAndEnc,
}

impl fmt::Display for OverlapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UidAndRCtr => write!(f, "UID and ReadCtr"),
            Self::UidAndTamper => write!(f, "UID and TamperStatus"),
            Self::RCtrAndTamper => write!(f, "ReadCtr and TamperStatus"),
            Self::UidAndMac => write!(f, "UID and MAC"),
            Self::RCtrAndMac => write!(f, "ReadCtr and MAC"),
            Self::TamperAndMac => write!(f, "TamperStatus and MAC"),
            Self::EncAndUid => write!(f, "EncFileData and UID"),
            Self::EncAndRCtr => write!(f, "EncFileData and ReadCtr"),
            Self::TamperInCiphertextHalf => {
                write!(
                    f,
                    "TamperStatus overlaps the ciphertext half of EncFileData"
                )
            }
            Self::PiccAndTamper => write!(f, "PICCData blob and TamperStatus"),
            Self::PiccAndMac => write!(f, "PICCData blob and MAC"),
            Self::PiccAndEnc => write!(f, "PICCData blob and EncFileData"),
        }
    }
}

/// Identifies which option byte in the file settings contained reserved bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedByte {
    FileOption,
    SdmOptions,
    SdmAccessRights0,
}

impl fmt::Display for ReservedByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileOption => write!(f, "FileOption"),
            Self::SdmOptions => write!(f, "SDMOptions"),
            Self::SdmAccessRights0 => write!(f, "SDMAccessRights[0]"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileSettingsError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("trailing bytes after file settings ({0} byte(s) left)")]
    TrailingBytes(usize),
    #[error("unknown FileType {0:#04x}")]
    UnknownFileType(u8),
    #[error("invalid access-condition nibble in {slot}: {value:#x}")]
    InvalidAccessNibble { slot: NibbleSlot, value: u8 },
    #[error("offset value exceeds 24-bit range: {0}")]
    OffsetOutOfRange(u32),
    #[error("encrypted file data length must be a positive multiple of 32, got {0}")]
    EncLengthInvalid(u32),
    #[error("MAC input offset must not exceed MAC placeholder offset")]
    MacInputAfterMac,
    #[error("encrypted file data range must lie within the MAC window")]
    EncOutsideMacWindow,
    #[error("reserved bit(s) set in {byte}: mask {mask:#04x}")]
    ReservedBitSet { byte: ReservedByte, mask: u8 },
    #[error("encrypted file data requires both UID and read counter mirroring")]
    EncRequiresBothMirrors,
    #[error("SDM mirror regions overlap: {0}")]
    MirrorsOverlap(OverlapKind),
    #[error("SDM flags in wire encoding are structurally inconsistent")]
    InvalidSdmFlags,
}
