// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::ResponseStatus;

/// Status word tagged with its framing.
///
/// The framing tells `ok()` which success code to expect.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum ResponseCode {
    /// ISO 7816 status word (CLA=`00` commands, PC/SC pseudo-APDUs). OK = `9000`.
    Iso { sw1: u8, sw2: u8 },
    /// DESFire-native status (CLA=`90` commands on NTAG 424 DNA). OK = `9100`.
    Desfire { sw1: u8, sw2: u8 },
}

impl ResponseCode {
    pub fn iso(sw1: u8, sw2: u8) -> Self {
        Self::Iso { sw1, sw2 }
    }

    pub fn desfire(sw1: u8, sw2: u8) -> Self {
        Self::Desfire { sw1, sw2 }
    }

    pub fn ok(&self) -> bool {
        matches!(
            self,
            Self::Iso {
                sw1: 0x90,
                sw2: 0x00
            } | Self::Desfire {
                sw1: 0x91,
                sw2: 0x00
            }
        )
    }

    pub fn code(&self) -> u16 {
        match self {
            Self::Iso { sw1, sw2 } | Self::Desfire { sw1, sw2 } => {
                ((*sw1 as u16) << 8) | (*sw2 as u16)
            }
        }
    }

    pub fn status(&self) -> ResponseStatus {
        if matches!(self, Self::Desfire { .. }) {
            match self.code() {
                0x9100 => ResponseStatus::OperationOk,
                0x911C => ResponseStatus::IllegalCommandCode,
                0x911E => ResponseStatus::IntegrityError,
                0x9140 => ResponseStatus::NoSuchKey,
                0x917E => ResponseStatus::LengthError,
                0x919D => ResponseStatus::PermissionDenied,
                0x919E => ResponseStatus::ParameterError,
                0x91AD => ResponseStatus::AuthenticationDelay,
                0x91AE => ResponseStatus::AuthenticationError,
                0x91AF => ResponseStatus::AdditionalFrame,
                0x91BE => ResponseStatus::BoundaryError,
                0x91CA => ResponseStatus::CommandAborted,
                0x91EE => ResponseStatus::MemoryError,
                0x91F0 => ResponseStatus::FileNotFound,
                code => ResponseStatus::Unknown(code),
            }
        } else {
            match self.code() {
                0x6700 => ResponseStatus::WrongLength,
                0x6982 => ResponseStatus::SecurityStatusNotSatisfied,
                0x6985 => ResponseStatus::ConditionsOfUseNotSatisfied,
                0x6A80 => ResponseStatus::IncorrectParametersInTheCommandDataField,
                0x6A82 => ResponseStatus::FileOrApplicationNotFound,
                0x6A86 => ResponseStatus::IncorrectParametersP1P2,
                0x6A87 => ResponseStatus::LcInconsistentWithParametersP1P2,
                0x6C00 => ResponseStatus::WrongLeField,
                c @ 0x6C01..=0x6CFF => ResponseStatus::WrongLeFieldExpected((c & 0xFF) as u8),
                0x6D00 => ResponseStatus::InstructionCodeNotSupportedOrInvalid,
                0x6E00 => ResponseStatus::ClassNotSupported,
                0x9000 => ResponseStatus::NormalProcessing,
                code => ResponseStatus::Unknown(code),
            }
        }
    }
}

impl core::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Iso { sw1, sw2 } => write!(f, "ISO SW={sw1:02X}{sw2:02X}"),
            Self::Desfire { sw1, sw2 } => write!(f, "DESFire SW={sw1:02X}{sw2:02X}"),
        }
    }
}
