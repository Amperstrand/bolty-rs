// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Types encoding information sent to or received from NTAG 424 DNA tags.

/// Length in bytes of a raw `Read_Sig` response: the tag's P-224 ECDSA
/// originality signature (`r ‖ s`, 28 bytes each, big-endian).
///
/// A wire-format constant, defined here (not in `crypto::originality`,
/// which is feature-gated) so the `Read_Sig` command compiles without
/// the `originality` feature.
pub const SIGNATURE_LEN: usize = 56;

pub mod cc;
mod configuration;
mod file;
pub mod file_settings;
mod key_number;
mod response_code;
mod response_status;
mod tt_status;
mod uid;
mod version;

pub use configuration::Configuration;
pub use file::File;
pub use file_settings::{
    Access, AccessRights, CommMode, FileSettingsError, FileSettingsUpdate, FileSettingsView,
};
pub use key_number::{KeyNumber, NonMasterKeyNumber};
pub(crate) use response_code::ResponseCode;
pub use response_status::ResponseStatus;
pub use tt_status::{TagTamperStatus, TagTamperStatusReadout};
pub use uid::Uid;
pub use version::Version;
