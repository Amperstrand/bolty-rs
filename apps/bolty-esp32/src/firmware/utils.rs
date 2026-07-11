use core::fmt::Write as _;

use crate::service::WorkflowResult;
use bolty_core::{
    assessment::CardState,
    config::{ErrorString, LnurlString},
    secret::CardKeys,
};
use heapless::String;
use ntag424::{CommMode, FileSettingsView, KeyNumber, types::file_settings::Access};
use std::vec::Vec;

use super::MAX_LINE_LEN;
use super::service::DiagnoseState;

pub(super) fn millis() -> u64 {
    let micros = unsafe { esp_idf_sys::esp_timer_get_time() };
    if micros <= 0 { 0 } else { micros as u64 / 1000 }
}

pub(super) fn scan_i2c_bus<I2C>(i2c: &mut I2C) -> Vec<u8>
where
    I2C: embedded_hal::i2c::I2c,
{
    let mut found = Vec::new();
    for address in 0x03..=0x77 {
        if i2c.write(address, &[0x00]).is_ok() {
            found.push(address);
        }
    }
    found
}

pub(super) fn copy_uid7(uid: &[u8]) -> Option<[u8; 7]> {
    if uid.len() != 7 {
        return None;
    }
    let mut out = [0u8; 7];
    out.copy_from_slice(uid);
    Some(out)
}

pub(super) fn uid_storage_from_fixed(uid: &[u8; 7]) -> Option<[u8; 12]> {
    let mut out = [0u8; 12];
    out[..7].copy_from_slice(uid);
    Some(out)
}

pub(super) fn push_uid_hex<const N: usize>(out: &mut String<N>, uid: &[u8]) -> core::fmt::Result {
    for byte in uid {
        write!(out, "{byte:02X}")?;
    }
    Ok(())
}

pub(super) fn ndef_ascii(bytes: &[u8]) -> String<MAX_LINE_LEN> {
    let mut out = String::<MAX_LINE_LEN>::new();
    for &byte in bytes {
        let ch = if (0x20..=0x7E).contains(&byte) {
            byte as char
        } else {
            '.'
        };
        if out.push(ch).is_err() {
            break;
        }
    }
    out
}

pub(super) fn copy_lnurl(value: &str) -> Option<LnurlString> {
    let mut out = LnurlString::new();
    out.push_str(value).ok()?;
    Some(out)
}

pub(super) fn looks_factory_default(file_settings: Option<&FileSettingsView>) -> bool {
    let Some(file_settings) = file_settings else {
        return false;
    };

    file_settings.file_size == 256
        && matches!(file_settings.comm_mode, CommMode::Plain)
        && file_settings.sdm.is_none()
        && matches!(file_settings.access_rights.read, Access::Free)
        && matches!(file_settings.access_rights.write, Access::Free)
        && matches!(file_settings.access_rights.read_write, Access::Free)
        && matches!(
            file_settings.access_rights.change,
            Access::Key(KeyNumber::Key0)
        )
}

pub(super) fn card_state_label(state: CardState) -> &'static str {
    match state {
        CardState::Blank => "blank",
        CardState::Provisioned(_) => "provisioned",
        CardState::Foreign => "foreign",
        CardState::Unknown => "unknown",
    }
}

pub(super) fn diagnose_state_label(state: DiagnoseState) -> &'static str {
    match state {
        DiagnoseState::Blank => "BLANK",
        DiagnoseState::Provisioned => "PROVISIONED",
        DiagnoseState::AuthDelay => "AUTH_DELAY",
        DiagnoseState::Inconsistent => "INCONSISTENT",
    }
}

pub(super) enum CounterDisplay {
    Value(u32),
    None,
}

impl core::fmt::Display for CounterDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CounterDisplay::Value(value) => write!(f, "{value}"),
            CounterDisplay::None => f.write_str("none"),
        }
    }
}

pub(super) fn workflow_error(message: &str) -> WorkflowResult {
    let mut out = ErrorString::new();
    if out.push_str(message).is_err() {
        let _ = out.push_str("workflow error");
    }
    WorkflowResult::Error(out)
}

pub(super) fn nfc_unavailable_result() -> WorkflowResult {
    workflow_error("nfc unavailable")
}

pub(super) fn workflow_error_debug<T: core::fmt::Debug>(error: &T) -> WorkflowResult {
    let mut out = ErrorString::new();
    if write!(out, "{error:?}").is_err() {
        let _ = out.push_str("debug fmt overflow");
    }
    WorkflowResult::Error(out)
}

pub(super) fn map_ntag_error<T>(error: &bolty_ntag::Error<T>) -> WorkflowResult
where
    T: core::error::Error + core::fmt::Debug,
{
    match error {
        err if bolty_ntag::is_authentication_delay(err) => WorkflowResult::AuthDelay,
        bolty_ntag::Error::Session(ntag424::SessionError::ErrorResponse(status)) => {
            log::warn!("ntag424 auth error: {:?}", status);
            WorkflowResult::AuthFailed
        }
        _ => workflow_error_debug(error),
    }
}
