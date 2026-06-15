//! NTAG424 Bolt Card workflows over any `ntag424::Transport` implementation.
//!
//! Implements the high-level card operations used by bolty-rs firmware:
//! `safe_inspect` (read-only card diagnostics + SDM verification), `burn`
//! (provision keys and SDM URL), `wipe` (factory reset), `check_key_versions`,
//! and `derive_keys` via NTAG424 key diversification.
//!
//! `#![no_std]`-compatible (uses `alloc`).
//!
//! Key types: `KeySet`, `BurnParams`, `BurnResult`, `WipeResult`,
//! `SafeInspectResult`, `Error`.

#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

use alloc::vec::Vec;
use ntag424::{
    AuthenticatedSession, File, FileSettingsView, KeyNumber, NonMasterKeyNumber, Session,
    SessionError, Transport, Uid, Version,
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, SdmVerification, Verifier, sdm_url_config},
    types::{
        ResponseStatus,
        file_settings::{CryptoMode, PiccData, Sdm},
    },
};

pub use bolty_core::constants::{FACTORY_KEY, KEY_VERSION_BLANK as FACTORY_KEY_VERSION};

pub type KeySet = [[u8; 16]; 5];

pub fn derive_keys(master_key: &[u8; 16], uid: &[u8; 7], system_id: &[u8]) -> KeySet {
    [
        diversify_ntag424(master_key, uid, KeyNumber::Key0, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key1, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key2, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key3, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key4, system_id),
    ]
}

#[derive(Debug)]
pub struct BurnParams<'a> {
    pub lnurl: &'a str,
    pub keys: KeySet,
    pub key_version: u8,
    pub current_key: [u8; 16],
    pub previous_keys: KeySet,
}

#[derive(Debug)]
pub struct BurnResult {
    pub uid: [u8; 7],
}

#[derive(Debug)]
pub struct WipeResult {
    pub uid: [u8; 7],
}

#[derive(Debug)]
pub struct SafeInspectResult {
    pub uid: [u8; 7],
    pub version: Option<Version>,
    pub file_settings: Option<FileSettingsView>,
    pub ndef_bytes: Option<Vec<u8>>,
    pub sdm_verification: Option<SdmVerification>,
}

#[derive(Debug)]
pub enum Error<T: core::error::Error + core::fmt::Debug> {
    Transport(T),
    SdmUrl(ntag424::sdm::SdmUrlError),
    Session(SessionError<T>),
    AuthenticationDelay,
    WrongCardType {
        vendor: u8,
        card_type: u8,
    },
    NdefVerificationFailed {
        written: usize,
        read_back: usize,
    },
    KeyVersionMismatch {
        key_number: u8,
        expected: u8,
        actual: u8,
    },
    SdmVerificationFailed,
}

impl<T: core::error::Error + core::fmt::Debug> From<SessionError<T>> for Error<T> {
    fn from(e: SessionError<T>) -> Self {
        match e {
            SessionError::ErrorResponse(ResponseStatus::AuthenticationDelay) => {
                Error::AuthenticationDelay
            }
            other => Error::Session(other),
        }
    }
}

impl<T: core::error::Error + core::fmt::Debug> From<ntag424::sdm::SdmUrlError> for Error<T> {
    fn from(e: ntag424::sdm::SdmUrlError) -> Self {
        Error::SdmUrl(e)
    }
}

/// Check if an error is an authentication delay response.
/// Authentication delay means the card has temporarily locked due to
/// too many failed auth attempts and will recover after a timeout.
pub fn is_authentication_delay<T: core::error::Error + core::fmt::Debug>(err: &Error<T>) -> bool {
    matches!(
        err,
        Error::AuthenticationDelay
            | Error::Session(SessionError::ErrorResponse(
                ResponseStatus::AuthenticationDelay,
            ))
    )
}

/// Check if a raw `SessionError` is an authentication delay.
/// Use this when calling ntag424 `Session` methods directly
/// (outside of `bolty_ntag` wrappers).
pub fn is_session_auth_delay<T: core::error::Error + core::fmt::Debug>(
    err: &SessionError<T>,
) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(ResponseStatus::AuthenticationDelay)
    )
}

/// Convert an `ntag424::Uid` to a fixed 7-byte array.
/// Returns all-zeros for random UIDs (which can't be used for key derivation).
pub fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

pub async fn read_uid<T: Transport>(transport: &mut T) -> Result<[u8; 7], Error<T::Error>> {
    let uid = Session::default().get_selected_uid(transport).await?;
    Ok(uid_to_fixed(&uid))
}

/// Pre-flight check: verify the card responds and is an NTAG424 DNA.
///
/// Returns the card UID on success, or an error if the card doesn't
/// respond or isn't an NTAG424 DNA (vendor=0x04, type=0x04).
pub async fn preflight<T: Transport>(transport: &mut T) -> Result<[u8; 7], Error<T::Error>> {
    let session = Session::default();

    let uid = session.get_selected_uid(transport).await?;
    let uid_fixed = uid_to_fixed(&uid);

    let version = session.get_version(transport).await?;

    if version.hw_vendor_id() != 0x04 || version.hw_type() != 0x04 {
        return Err(Error::WrongCardType {
            vendor: version.hw_vendor_id(),
            card_type: version.hw_type(),
        });
    }

    Ok(uid_fixed)
}

pub async fn safe_inspect<T: Transport>(
    transport: &mut T,
    k1: Option<&[u8; 16]>,
    k2: Option<&[u8; 16]>,
) -> Result<SafeInspectResult, Error<T::Error>> {
    let mut session = Session::default();
    let uid = uid_to_fixed(&session.get_selected_uid(transport).await?);

    let version = session.get_version(transport).await.ok();
    let file_settings = session.get_file_settings(transport, File::Ndef).await.ok();

    let mut buf = [0u8; 256];
    let ndef_bytes = session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
        .ok()
        .map(|len| {
            // SAFETY: clamped via .min(buf.len()).
            #[allow(clippy::indexing_slicing)]
            {
                let clamped = len.min(buf.len());
                Vec::from(&buf[..clamped])
            }
        });

    let sdm_verification = match (&file_settings, &ndef_bytes, k1, k2) {
        (Some(file_settings), Some(ndef_bytes), Some(k1), Some(k2)) => file_settings
            .sdm
            .and_then(|sdm| Verifier::try_new(&sdm, CryptoMode::Aes).ok())
            .and_then(|verifier| verifier.verify_with_meta_key(ndef_bytes, k2, k1).ok()),
        _ => None,
    };

    Ok(SafeInspectResult {
        uid,
        version,
        file_settings,
        ndef_bytes,
        sdm_verification,
    })
}

pub async fn burn<T: Transport>(
    transport: &mut T,
    params: &BurnParams<'_>,
    rnd_a: [u8; 16],
) -> Result<BurnResult, Error<T::Error>> {
    // Bolt Card standard: K1 = PICC encryption, K2 = MAC verification.
    let sdm_opts = SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..SdmUrlOptions::new()
    };
    let plan = sdm_url_config(params.lnurl, CryptoMode::Aes, sdm_opts)?;

    let session = Session::default();

    let uid = session.get_selected_uid(transport).await?;
    let uid_fixed = uid_to_fixed(&uid);

    let session = session
        .authenticate_aes(transport, KeyNumber::Key0, &params.current_key, rnd_a)
        .await?;

    let (settings, s) = session.get_file_settings(transport, File::Ndef).await?;
    let mut session = if settings.sdm.is_some() {
        let update = settings.into_update().with_sdm(Sdm::disabled());
        s.change_file_settings(transport, File::Ndef, &update)
            .await?
    } else {
        s
    };

    session
        .write_file_plain(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await?;

    let mut read_buf = [0u8; 256];
    let read_len = session
        .read_file_plain(transport, File::Ndef, 0, 0, &mut read_buf)
        .await?;
    // SAFETY: read_buf is [u8; 256], NDEF templates are always <= 256 bytes.
    #[allow(clippy::indexing_slicing)]
    if read_len < plan.ndef_bytes.len() || read_buf[..plan.ndef_bytes.len()] != plan.ndef_bytes[..]
    {
        return Err(Error::NdefVerificationFailed {
            written: plan.ndef_bytes.len(),
            read_back: read_len,
        });
    }

    let (settings, session) = session.get_file_settings(transport, File::Ndef).await?;
    let session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &settings.into_update().with_sdm(plan.sdm_settings),
        )
        .await?;

    let (verify_settings, mut session) = session.get_file_settings(transport, File::Ndef).await?;
    if verify_settings.sdm.is_none() {
        return Err(Error::SdmVerificationFailed);
    }

    let key_updates: [(NonMasterKeyNumber, KeyNumber, &[u8; 16], &[u8; 16]); 4] = [
        (
            NonMasterKeyNumber::Key1,
            KeyNumber::Key1,
            &params.keys[1],
            &params.previous_keys[1],
        ),
        (
            NonMasterKeyNumber::Key2,
            KeyNumber::Key2,
            &params.keys[2],
            &params.previous_keys[2],
        ),
        (
            NonMasterKeyNumber::Key3,
            KeyNumber::Key3,
            &params.keys[3],
            &params.previous_keys[3],
        ),
        (
            NonMasterKeyNumber::Key4,
            KeyNumber::Key4,
            &params.keys[4],
            &params.previous_keys[4],
        ),
    ];

    for (key_no, kn, new_key, old_key) in key_updates.iter() {
        let s = session
            .change_key(transport, *key_no, new_key, params.key_version, old_key)
            .await?;
        let (v, s2) = s.get_key_version(transport, *kn).await?;
        if v != params.key_version {
            return Err(Error::KeyVersionMismatch {
                key_number: *kn as u8,
                expected: params.key_version,
                actual: v,
            });
        }
        session = s2;
    }

    let _session = session
        .change_master_key(transport, &params.keys[0], params.key_version)
        .await?;

    let verify_session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &params.keys[0], rnd_a)
        .await?;
    let (final_settings, _) = verify_session
        .get_file_settings(transport, File::Ndef)
        .await?;
    if final_settings.sdm.is_none() {
        return Err(Error::SdmVerificationFailed);
    }

    Ok(BurnResult { uid: uid_fixed })
}

pub async fn wipe<T: Transport>(
    transport: &mut T,
    keys: &KeySet,
    rnd_a: [u8; 16],
) -> Result<WipeResult, Error<T::Error>> {
    let session = Session::default();

    let uid = session.get_selected_uid(transport).await?;
    let uid_fixed = uid_to_fixed(&uid);

    let session = session
        .authenticate_aes(transport, KeyNumber::Key0, &keys[0], rnd_a)
        .await?;

    let (settings, session) = session.get_file_settings(transport, File::Ndef).await?;
    let update = settings.into_update().with_sdm(Sdm::disabled());
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await?;

    // NDEF Type 4 Tag spec: first 2 bytes = NLEN (big-endian length of NDEF
    // message). NLEN=0 means empty NDEF — no records (NFC Forum NDEF Type 4
    // Tag §4.1). This is the spec-correct way to mark the file as empty.
    let empty_ndef = [0x00u8, 0x00];
    session
        .write_file_plain(transport, File::Ndef, 0, &empty_ndef)
        .await?;

    let key_updates: [(NonMasterKeyNumber, KeyNumber, &[u8; 16]); 4] = [
        (NonMasterKeyNumber::Key1, KeyNumber::Key1, &keys[1]),
        (NonMasterKeyNumber::Key2, KeyNumber::Key2, &keys[2]),
        (NonMasterKeyNumber::Key3, KeyNumber::Key3, &keys[3]),
        (NonMasterKeyNumber::Key4, KeyNumber::Key4, &keys[4]),
    ];

    let mut session = session;
    for (key_no, kn, old_key) in key_updates.iter() {
        let s = session
            .change_key(
                transport,
                *key_no,
                &FACTORY_KEY,
                FACTORY_KEY_VERSION,
                old_key,
            )
            .await?;
        let (v, s2) = s.get_key_version(transport, *kn).await?;
        if v != FACTORY_KEY_VERSION {
            return Err(Error::KeyVersionMismatch {
                key_number: *kn as u8,
                expected: FACTORY_KEY_VERSION,
                actual: v,
            });
        }
        session = s2;
    }

    let _session = session
        .change_master_key(transport, &FACTORY_KEY, FACTORY_KEY_VERSION)
        .await?;

    let verify_session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await?;
    let (final_settings, _) = verify_session
        .get_file_settings(transport, File::Ndef)
        .await?;
    if let Some(ref sdm) = final_settings.sdm {
        let has_picc = !matches!(sdm.picc_data(), PiccData::None);
        let has_mac = sdm.file_read().is_some();
        if has_picc || has_mac {
            return Err(Error::SdmVerificationFailed);
        }
    }

    Ok(WipeResult { uid: uid_fixed })
}

pub async fn check_key_versions<T: Transport>(
    transport: &mut T,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<[u8; 5], Error<T::Error>> {
    let session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, key, rnd_a)
        .await?;

    let key_numbers = [
        KeyNumber::Key0,
        KeyNumber::Key1,
        KeyNumber::Key2,
        KeyNumber::Key3,
        KeyNumber::Key4,
    ];
    let mut versions = [0u8; 5];
    let mut session = session;
    // SAFETY: i comes from enumerate over key_numbers (5 items), versions is [u8; 5].
    #[allow(clippy::indexing_slicing)]
    for (i, kn) in key_numbers.into_iter().enumerate() {
        let (v, s) = session.get_key_version(transport, kn).await?;
        versions[i] = v;
        session = s;
    }

    Ok(versions)
}
