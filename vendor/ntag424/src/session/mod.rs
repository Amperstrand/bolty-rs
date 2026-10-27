// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use core::error::Error;

use thiserror::Error;

use crate::Transport;
use crate::commands::{
    SecureChannel, authenticate_ev2_first_aes, authenticate_ev2_first_lrp,
    authenticate_ev2_non_first_aes, authenticate_ev2_non_first_lrp, change_file_settings,
    change_key, change_master_key, get_card_uid, get_file_counters, get_file_settings,
    get_file_settings_mac, get_key_version, get_tt_status, get_version, get_version_mac,
    iso_read_binary, iso_select_ef_by_fid, iso_update_binary, read_data_full, read_data_mac,
    read_data_plain, select_ndef_application, set_configuration, write_data_full, write_data_mac,
    write_data_plain,
};
#[cfg(feature = "originality")]
use crate::commands::{read_sig, read_sig_mac};
#[cfg(feature = "originality")]
use crate::crypto::originality::{self, OriginalityError};
use crate::crypto::suite::{AesSuite, LrpSuite, SessionSuite};
use crate::types::{
    CommMode, Configuration, File, FileSettingsError, FileSettingsView, KeyNumber,
    NonMasterKeyNumber, ResponseStatus, TagTamperStatusReadout, Uid, Version,
};

mod authenticated;
mod authenticated_session;
mod unauthenticated;

pub use authenticated::{Authenticated, EncryptedSession};
pub use authenticated_session::AuthenticatedSession;
pub use unauthenticated::Unauthenticated;

#[cfg(feature = "originality")]
pub use unauthenticated::FactoryStateCheckResult;

pub type UnauthenticatedSession = Session<Unauthenticated>;

#[cfg(test)]
mod tests;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SessionError<E: Error + core::fmt::Debug> {
    #[error(transparent)]
    Transport(#[from] E),
    #[error("error response: {0:?}")]
    ErrorResponse(ResponseStatus),
    #[error("unexpected response length: got {got}, expected {expected}")]
    UnexpectedLength { got: usize, expected: usize },
    #[error("invalid command parameter {parameter}: {reason} (got {value})")]
    InvalidCommandParameter {
        parameter: &'static str,
        value: usize,
        reason: &'static str,
    },
    #[error("APDU body too large: got {got}, maximum {max}")]
    ApduBodyTooLarge { got: usize, max: usize },
    #[error(transparent)]
    FileSettings(FileSettingsError),
    #[cfg(feature = "originality")]
    #[error("originality verification failed: {0:?}")]
    OriginalityVerificationFailed(OriginalityError),
    /// Authentication validation failed.
    ///
    /// The tag's response did not match what the host computed. Typical
    /// causes: wrong key or tampered response, but can be command specific.
    ///
    /// - AES (NT4H2421Gx §9.1.5): the decrypted round-trip nonce did not
    ///   match the nonce the host sent.
    /// - LRP (NT4H2421Gx §9.2.5, §10.4.3): the auth-mode byte, the tag's
    ///   response MAC, or the echoed host capabilities in the decrypted
    ///   Part 2 payload did not validate.
    #[error("authentication mismatch")]
    AuthenticationMismatch,
    /// A response MAC did not verify.
    ///
    /// The trailing 8-byte response MAC did not match the value the host
    /// computed over the response data and session state (NT4H2421Gx §9.1.9).
    /// Wrong session keys, tampered response, or out-of-sync command counter
    /// can all cause this.
    #[error("response MAC mismatch")]
    ResponseMacMismatch,
    /// A cipher buffer was not a positive multiple of 16 bytes.
    ///
    /// All AES-CBC and LRP encrypted payloads must be padded to a 16-byte
    /// boundary before encryption (ISO/IEC 9797-1 Method 2). This error
    /// indicates a library bug: callers of `SecureChannel::encrypt_command`
    /// and `SecureChannel::decrypt_response` must guarantee alignment before
    /// calling.
    #[error("cipher buffer length {0} is not a positive multiple of 16")]
    NotBlockAligned(usize),
    #[error("tag is not in factory state: {0}")]
    NotFactoryState(&'static str),
}

/// An NTAG 424 DNA session.
///
/// ## Authentication state
///
/// The type parameter `S` tracks the authentication state at compile time:
///
/// | Type | Meaning |
/// |---|---|
/// | `Session<Unauthenticated>` | No authenticated session established; only plain-mode commands available. |
/// | `Session<Authenticated<AesSuite>>` | Authenticated using AES-128. |
/// | `Session<Authenticated<LrpSuite>>` | Authenticated using LRP. |
///
/// Start with [`Session::default()`] (equivalent to `Session<Unauthenticated>`),
/// then call an authentication method such as [`Session::authenticate_aes`].
/// Authentication consumes `self` and, on success, returns a session in the new
/// state. On failure the session is dropped and you must start over from a fresh
/// [`Session::default()`].
///
/// Authenticated operations are provided by [`AuthenticatedSession`], implemented
/// for `Session<Authenticated<AesSuite>>`, `Session<Authenticated<LrpSuite>>`,
/// and the type-erased [`EncryptedSession`] wrapper.
pub struct Session<S> {
    state: S,
    /// Whether the NDEF application is selected.
    ///
    /// Tracks whether AID `D2760000850101` has been selected on the
    /// transport since the last power-on or deselect.
    ndef_selected: bool,
    /// The currently selected EF File ID.
    ///
    /// `None` means no EF has been selected since the last application
    /// select.
    ef_selected: Option<u16>,
}

impl<S> Session<S> {
    /// Read the UID as seen during card selection phase by the NFC reader.
    ///
    /// In random ID mode the value returned here is the randomized ID, not
    /// the permanent one. The actual UID can be read using [`AuthenticatedSession::get_uid`],
    /// which returns the permanent UID even when the tag is in random-ID mode.
    pub async fn get_selected_uid<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Uid, SessionError<T::Error>> {
        // This is implemented for all session states because
        // the selected UID is retrieved from the reader, no communication with the PICC
        // is done.

        let data = transport.get_uid().await?;
        let data = data.as_ref();
        match data.len() {
            7 => {
                let mut uid = [0u8; 7];
                uid.copy_from_slice(data);
                Ok(Uid::Fixed(uid))
            }
            4 => {
                let mut uid = [0u8; 4];
                uid.copy_from_slice(data);
                Ok(Uid::Random(uid))
            }
            got => Err(SessionError::UnexpectedLength { got, expected: 7 }),
        }
    }
}
