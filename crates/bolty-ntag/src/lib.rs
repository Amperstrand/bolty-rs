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

use alloc::string::String;
use alloc::string::ToString;
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

pub struct NdefUri {
    pub url: String,
    pub picc_hex: Option<String>,
    pub mac_hex: Option<String>,
}

const URI_PREFIXES: &[&str] = &["", "http://www.", "https://www.", "http://", "https://"];

pub fn parse_ndef_uri(data: &[u8]) -> Option<NdefUri> {
    if data.len() < 4 {
        return None;
    }
    let nlen = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    if nlen < 5 || data.len() < 2 + nlen {
        return None;
    }
    let msg = data.get(2..2 + nlen)?;

    let flags = *msg.first()?;
    let sr = (flags & 0x10) != 0;
    let il = (flags & 0x08) != 0;

    let type_len = usize::from(*msg.get(1)?);
    let header_len = if sr { 3 } else { 6 };

    let payload_len = if sr {
        usize::from(*msg.get(2)?)
    } else {
        u32::from_be_bytes([*msg.get(2)?, *msg.get(3)?, *msg.get(4)?, *msg.get(5)?]) as usize
    };

    if type_len != 1 || *msg.get(header_len)? != b'U' {
        return None;
    }

    let mut payload_offset = header_len + type_len;
    if il {
        let id_len = usize::from(*msg.get(payload_offset)?);
        payload_offset = payload_offset.checked_add(1)?.checked_add(id_len)?;
    }

    let payload_end = payload_offset.checked_add(payload_len)?;
    let payload = msg.get(payload_offset..payload_end)?;
    if payload.is_empty() {
        return None;
    }

    let prefix_code = usize::from(*payload.first()?);
    let prefix = URI_PREFIXES.get(prefix_code).copied().unwrap_or("");
    let uri = payload.get(1..)?;
    let uri_str = core::str::from_utf8(uri).ok()?.trim_end_matches('\0');
    let url = alloc::format!("{prefix}{uri_str}");

    let (picc_hex, mac_hex) = match bolty_core::picc::extract_p_and_c(uri_str) {
        Some((p, c)) => (Some(p.to_string()), Some(c.to_string())),
        None => (None, None),
    };

    Some(NdefUri {
        url,
        picc_hex,
        mac_hex,
    })
}

#[cfg(test)]
mod ndef_tests {
    use super::*;
    use alloc::vec;

    const MINIMAL_NDEF: &[u8] = &[
        0x00, 0x09, 0xD1, 0x01, 0x05, 0x55, 0x04, 0x61, 0x62, 0x63, 0x64,
    ];

    const BOLTCARD_NDEF: &[u8] = &[
        0x00, 0x4F, 0xD1, 0x01, 0x4B, 0x55, 0x04, b'b', b'o', b'l', b't', b'c', b'a', b'r', b'd',
        b'p', b'o', b'c', b'.', b'p', b's', b'b', b't', b'.', b'm', b'e', b'/', b'?', b'p', b'=',
        b'A', b'B', b'C', b'D', b'E', b'F', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
        b'9', b'A', b'B', b'C', b'D', b'E', b'F', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'&', b'c', b'=', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
        b'A', b'B', b'C', b'D', b'E', b'F',
    ];

    #[test]
    fn parse_minimal_ndef() {
        let parsed = parse_ndef_uri(MINIMAL_NDEF).unwrap();
        assert_eq!(parsed.url, "https://abcd");
        assert!(parsed.picc_hex.is_none());
        assert!(parsed.mac_hex.is_none());
    }

    #[test]
    fn parse_boltcard_ndef() {
        let parsed = parse_ndef_uri(BOLTCARD_NDEF).unwrap();
        assert!(parsed.url.starts_with("https://boltcardpoc.psbt.me/?p="));
        assert_eq!(
            parsed.picc_hex.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789")
        );
        assert_eq!(parsed.mac_hex.as_deref(), Some("0123456789ABCDEF"));
    }

    #[test]
    fn parse_empty_ndef() {
        assert!(parse_ndef_uri(&[0x00, 0x00]).is_none());
    }

    #[test]
    fn parse_short_ndef() {
        assert!(parse_ndef_uri(&[0x00, 0x01, 0xD1]).is_none());
    }

    #[test]
    fn parse_non_uri_ndef() {
        let data = &[
            0x00, 0x05, 0xD1, 0x01, 0x01, 0x54, 0x02, 0x65, 0x6e, 0x68, 0x69,
        ];
        assert!(parse_ndef_uri(data).is_none());
    }

    #[test]
    fn parse_wrong_prefix_code() {
        let data = &[0x00, 0x07, 0xD1, 0x01, 0x03, 0x55, 0xFF, b'x', b'y'];
        let parsed = parse_ndef_uri(data).unwrap();
        assert_eq!(parsed.url, "xy");
    }

    #[test]
    fn parse_long_record_non_sr() {
        let mut data = vec![0x00, 0x00];
        data.push(0xC1);
        data.push(0x01);
        data.extend_from_slice(&100u32.to_be_bytes());
        data.push(0x55);
        data.push(0x04);
        data.extend(core::iter::repeat(b'x').take(99));
        let nlen = (data.len() - 2) as u16;
        data[0..2].copy_from_slice(&nlen.to_be_bytes());
        let parsed = parse_ndef_uri(&data).unwrap();
        assert!(parsed.url.starts_with("https://"));
        assert_eq!(parsed.url.len(), 8 + 100 - 1);
    }

    #[test]
    fn parse_with_id_length_present() {
        let data = vec![
            0x00, 0x0A, 0xD9, 0x01, 0x04, 0x55, 0x01, 0x42, 0x04, b'x', b'y', b'z',
        ];
        let parsed = parse_ndef_uri(&data).unwrap();
        assert_eq!(parsed.url, "https://xyz");
    }

    #[test]
    fn parse_truncated_payload() {
        let data = &[
            0x00, 0x10, 0xD1, 0x01, 0x20, 0x55, 0x04, b'h', b'e', b'l', b'l', b'o',
        ];
        assert!(parse_ndef_uri(data).is_none());
    }

    #[test]
    fn parse_sdm_url_config_ndef_template() {
        let opts = SdmUrlOptions {
            picc_key: KeyNumber::Key1,
            mac_key: KeyNumber::Key2,
            ..SdmUrlOptions::new()
        };
        let url = "https://card.bolt.local/lnurl?[[p={picc:uid+ctr}&cmac={mac}";
        let plan = sdm_url_config(url, CryptoMode::Aes, opts).unwrap();

        let parsed = parse_ndef_uri(&plan.ndef_bytes).expect("should parse sdm_url_config output");
        assert!(parsed.url.contains("card.bolt.local"));
    }
}
