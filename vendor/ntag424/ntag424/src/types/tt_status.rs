// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// One TagTamper status byte as returned by `GetTTStatus`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TagTamperStatus {
    /// Loop is still closed.
    Close,
    /// Detection is open.
    ///
    /// Once the permanent status returned by [`TagTamperStatusReadout::permanent`]
    /// becomes open, it remains open.
    Open,
    /// Tag tamper detection is not [enabled](`crate::types::Configuration::with_tag_tamper_enabled`).
    Invalid,
    /// Any non-specified byte returned by the PICC.
    Unknown(u8),
}

impl From<u8> for TagTamperStatus {
    fn from(value: u8) -> Self {
        match value {
            0x43 => Self::Close,
            0x4F => Self::Open,
            0x49 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }
}

/// TagTamper status pair returned by [`AuthenticatedSession::get_tt_status`](`crate::AuthenticatedSession::get_tt_status`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TagTamperStatusReadout {
    permanent: TagTamperStatus,
    current: TagTamperStatus,
}

impl TagTamperStatusReadout {
    pub(crate) fn new(permanent: u8, current: u8) -> Self {
        Self {
            permanent: permanent.into(),
            current: current.into(),
        }
    }

    pub fn permanent(&self) -> TagTamperStatus {
        self.permanent
    }

    pub fn current(&self) -> TagTamperStatus {
        self.current
    }

    /// Returns `true` if the tag has been tampered with, i.e. if either the permanent or current status is open or unknown.
    pub fn is_tampered(&self) -> bool {
        matches!(
            (self.permanent, self.current),
            (TagTamperStatus::Open, _) | (_, TagTamperStatus::Open)
        )
    }
}
