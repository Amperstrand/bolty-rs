// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

#[cfg(feature = "alloc")]
use alloc::borrow::ToOwned;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use thiserror::Error;

use crate::types::KeyNumber;
use crate::types::file_settings::{
    CryptoMode, CtrRetAccess, EncFileData, EncLength, EncryptedContent, FileRead,
    FileSettingsError, MacWindow, Offset, PiccData, PlainMirror, ReadCtrFeatures, ReadCtrMirror,
    Sdm,
};

const URI_AT: u32 = 7;
const DEFAULT_CONST_PLAN_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Error returned when parsing an SDM URL template.
#[cfg(feature = "alloc")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdmUrlError {
    #[error("{{mac}} placeholder is required")]
    MissingMac,
    #[error("{{picc...}} is mutually exclusive with {{uid}} and {{ctr}}")]
    PiccWithPlainMirrors,
    #[error("template requires at least one of {{picc...}}, {{uid}}, {{ctr}}, {{tt}}")]
    NoMirror,
    #[error("duplicate placeholder: {0}")]
    DuplicatePlaceholder(&'static str),
    #[error("encrypted file data requires both UID and SDMReadCtr mirroring")]
    EncFileDataRequiresUidAndCtr,
    #[error("encrypted file data range must be a positive multiple of 32 ASCII bytes, got {0}")]
    InvalidEncRangeLength(u32),
    #[error("invalid placeholder: {0}")]
    InvalidPlaceholder(String),
    #[error("unterminated {0}")]
    Unterminated(&'static str),
    #[error("unexpected {0}")]
    UnexpectedMarker(&'static str),
    #[error("duplicate {0}")]
    DuplicateRange(&'static str),
    #[error("{0} is not allowed inside [...]")]
    PlaceholderInEncRange(&'static str),
    #[error("nested {0} is not allowed")]
    NestedRange(&'static str),
    #[error("the [[ marker must appear before {{mac}}")]
    MacStartAfterMac,
    #[error("NDEF file too long: {got} bytes, max {max}")]
    FileTooLong { got: usize, max: u16 },
    #[error(transparent)]
    FileSettings(#[from] FileSettingsError),
}

/// Options controlling key assignment and limits for SDM URL plan builders.
#[derive(Debug, Clone, Copy)]
pub struct SdmUrlOptions {
    /// Key used for `{picc...}`, if used.
    pub picc_key: KeyNumber,
    /// Key used for MAC generation.
    pub mac_key: KeyNumber,
    /// Access rights for the SDM read counter.
    pub ctr_ret: CtrRetAccess,
    /// Maximum allowed NDEF file size.
    ///
    /// This is used to reject templates that would
    /// result in file sizes that cannot be written to the tag.
    /// The default is 256, which is the maximum size of the NDEF file.
    pub max_file_size: u16,
}

impl SdmUrlOptions {
    /// Returns the default SDM URL options.
    ///
    /// Defaults: `picc_key = Key2`, `mac_key = Key2`,
    /// `ctr_ret = NoAccess`, `max_file_size = 256`.
    pub const fn new() -> Self {
        Self {
            picc_key: KeyNumber::Key2,
            mac_key: KeyNumber::Key2,
            ctr_ret: CtrRetAccess::NoAccess,
            max_file_size: 256,
        }
    }
}

impl Default for SdmUrlOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Output of [`sdm_url_config`].
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct SdmUrlConfig {
    /// NDEF file content to be written to the tag.
    pub ndef_bytes: Vec<u8>,
    /// Settings to be applied with [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
    pub sdm_settings: Sdm,
    /// Byte offset within `ndef_bytes` at which the abbreviated URI body starts.
    ///
    /// Always `7`: two-byte NLEN field, 0xD1 record header, 0x01 type length,
    /// one-byte payload length, 0x55 URI record type, one-byte URI prefix code.
    /// The prefix code byte itself sits at `ndef_bytes[offset - 1]`.
    pub offset: usize,
    /// Number of bytes stripped from the beginning of the input URL and encoded
    /// as the single URI prefix code byte at `ndef_bytes[offset - 1]`.
    ///
    /// For example, `8` for `https://`, `0` if the URL had no recognized prefix.
    ///
    /// Use together with [`offset`](`SdmUrlConfig::offset`) to convert an NDEF
    /// byte offset (as found in [`sdm_settings`](`SdmUrlConfig::sdm_settings`))
    /// to a character index in the original URL. This adjustment can be applied to a
    /// [`Verifier`](`crate::sdm::Verifier`) so
    /// that [`verify`](`crate::sdm::Verifier::verify`) can be called against
    /// the full URL bytes instead of raw NDEF bytes:
    ///
    /// ```
    /// # #[cfg(feature = "sdm")]
    /// # fn main() {
    /// use ntag424::sdm::{Verifier, parse_ndef_uri, sdm_url_config, SdmUrlOptions};
    /// use ntag424::types::file_settings::CryptoMode;
    /// use ntag424::types::KeyNumber;
    ///
    /// let opts = SdmUrlOptions {
    ///     picc_key: KeyNumber::Key1,
    ///     mac_key: KeyNumber::Key2,
    ///     ..SdmUrlOptions::default()
    /// };
    /// let config = sdm_url_config(
    ///     "https://example.com/?p={picc}&m={mac}",
    ///     CryptoMode::Lrp,
    ///     opts,
    /// )
    /// .unwrap();
    ///
    /// // "https://" is 8 bytes; prefix_len records how many characters of the
    /// // original URL were compressed into the single NDEF prefix-code byte.
    /// assert_eq!(config.prefix_len, 8);
    ///
    /// // parse_ndef_uri reconstructs the full URL from the NDEF bytes.
    /// let url = parse_ndef_uri(&config.ndef_bytes).unwrap();
    /// assert!(url.as_ref().starts_with("https://example.com/"));
    ///
    /// // Shift all internal NDEF byte offsets to URL character indices so that
    /// // Verifier::verify can be called directly against the full URL string.
    /// let raw_verifier = Verifier::try_new(&config.sdm_settings, CryptoMode::Lrp).unwrap();
    /// let url_verifier = raw_verifier
    ///     .with_offset(config.prefix_len as i32 - config.offset as i32)
    ///     .unwrap();
    /// assert_eq!(url_verifier.start(), raw_verifier.start() + 1);
    /// # }
    /// # #[cfg(not(feature = "sdm"))]
    /// # fn main() {}
    /// ```
    pub prefix_len: usize,
    /// NFC Forum URI Record prefix code stored at `ndef_bytes[offset - 1]`.
    ///
    /// `0x00` means the URL had no recognized prefix and is stored verbatim.
    /// See the table in [`sdm_url_config`] for the full code-to-prefix mapping.
    pub prefix_code: u8,
}

impl SdmUrlConfig {
    /// Returns the URI prefix string corresponding to `prefix_code`, if any.
    pub fn prefix(&self) -> Option<&'static [u8]> {
        if self.prefix_code == 0 {
            return Some(b"");
        }
        NDEF_URI_PREFIXES
            .iter()
            .find(|(code, _)| *code == self.prefix_code)
            .map(|(_, prefix)| *prefix)
    }

    /// Returns `true` if the configuration includes a mirror of the PICC UID.
    ///
    /// This is true if the template includes `{picc:uid}`, `{picc:uid+ctr}`/`{picc}`,
    /// or a plain `{uid}` mirror, and false otherwise.
    pub fn mirrors_uid(&self) -> bool {
        matches!(
            self.sdm_settings.picc_data(),
            PiccData::Plain(PlainMirror::Uid { .. })
                | PiccData::Plain(PlainMirror::Both { .. })
                | PiccData::Encrypted {
                    content: EncryptedContent::Uid,
                    ..
                }
                | PiccData::Encrypted {
                    content: EncryptedContent::Both(_),
                    ..
                }
        )
    }

    /// Returns `true` if the configuration includes a mirror of the SDM read counter.
    pub fn mirrors_ctr(&self) -> bool {
        matches!(
            self.sdm_settings.picc_data(),
            PiccData::Plain(PlainMirror::RCtr { .. })
                | PiccData::Plain(PlainMirror::Both { .. })
                | PiccData::Encrypted {
                    content: EncryptedContent::RCtr(_) | EncryptedContent::Both(_),
                    ..
                }
        )
    }
}

/// Fixed-capacity byte buffer returned by the hidden const SDM URL builder.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstNdefBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> ConstNdefBytes<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    const fn push(&mut self, byte: u8) -> Result<(), TemplateCoreError> {
        if self.len == N {
            return Err(TemplateCoreError::OutputBufferTooSmall {
                needed: self.len + 1,
                capacity: N,
            });
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    const fn push_zeroes(&mut self, count: usize) -> Result<(), TemplateCoreError> {
        let mut i = 0;
        while i < count {
            match self.push(b'0') {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
            i += 1;
        }
        Ok(())
    }

    const fn extend_bytes(
        &mut self,
        src: &[u8],
        start: usize,
        count: usize,
    ) -> Result<(), TemplateCoreError> {
        let mut i = 0;
        while i < count {
            match self.push(src[start + i]) {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
            i += 1;
        }
        Ok(())
    }
}

/// Output of the hidden const SDM URL builder.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstSdmNdefPlan<const N: usize> {
    pub ndef_bytes: ConstNdefBytes<N>,
    pub sdm_settings: Sdm,
    pub prefix_len: usize,
    pub prefix_code: u8,
}

#[doc(hidden)]
pub type __ConstSdmNdefPlan<const N: usize> = ConstSdmNdefPlan<N>;

#[doc(hidden)]
pub const __SDM_URL_PLAN_CAPACITY: usize = DEFAULT_CONST_PLAN_CAPACITY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiccContent {
    Uid,
    Ctr,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placeholder {
    Uid,
    Ctr,
    Picc(PiccContent),
    Tt,
    Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateCoreError {
    MissingMac,
    PiccWithPlainMirrors,
    NoMirror,
    DuplicatePlaceholder(&'static str),
    EncFileDataRequiresUidAndCtr,
    InvalidEncRangeLength(u32),
    InvalidPlaceholder { start: usize, end: usize },
    Unterminated(&'static str),
    UnexpectedMarker(&'static str),
    DuplicateRange(&'static str),
    PlaceholderInEncRange(&'static str),
    NestedRange(&'static str),
    MacStartAfterMac,
    OutputBufferTooSmall { needed: usize, capacity: usize },
    FileTooLong { got: usize, max: u16 },
    FileSettings(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTemplate<const N: usize> {
    uri_content: ConstNdefBytes<N>,
    uid_offset: Option<u32>,
    ctr_offset: Option<u32>,
    picc: Option<(u32, PiccContent)>,
    tt_offset: Option<u32>,
    mac_offset: u32,
    mac_input: u32,
    enc_range: Option<(u32, u32)>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
/// Create SDM configuration from a URL template string.
///
/// Converts a URL string with placeholder tokens into the NDEF file content
/// and [`SdmUrlConfig`] object. The NDEF file content must be written to the tag,
/// and settings must be applied with [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
///
/// # Placeholders
///
/// | Token                | Expanded length                    | Notes |
/// |----------------------|------------------------------------|-------|
/// | `{uid}`              | 14 ASCII hex chars                 | Plain UID mirror |
/// | `{ctr}`              | 6 ASCII hex chars                  | Plain SDMReadCtr mirror |
/// | `{picc}`             | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with UID + counter |
/// | `{picc:uid}`         | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with UID only |
/// | `{picc:ctr}`         | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with counter only |
/// | `{picc:uid+ctr}`     | 32 (AES) / 48 (LRP) ASCII hex chars | Explicit UID + counter form |
/// | `{tt}`               | 2 ASCII chars                      | Tag tamper status |
/// | `{mac}`              | 16 ASCII hex chars                 | SDMMAC; **always required** |
///
/// `{picc...}` is mutually exclusive with plain `{uid}` / `{ctr}`.
///
/// There is also a [`sdm_url_config!`](`crate::sdm_url_config!`)
/// macro for compile time evaluation.
///
/// # Range annotations
///
/// - `[[` marks the explicit MAC start. The MAC still ends at `{mac}`. If
///   omitted, the MAC window starts at the beginning of the abbreviated URI
///   body (the part after the NDEF URI prefix code).
/// - `[...]` reserves an encrypted file data window. The bracket contents are used
///   only to define the resulting ASCII length, and are rendered as `'0'`
///   bytes in the initial NDEF file. `{uid}`, `{ctr}`, `{picc...}`, and
///   `{mac}` are rejected inside this range; `{tt}` is allowed.
///
/// Escape reserved syntax with backslash, e.g. `\{`, `\[`, `\]`, `\\`.
///
/// # URI prefix recognition
///
/// The following URL prefixes are recognized and compressed to a single code
/// byte in the NDEF file (NFC Forum URI Record Type Definition §3.2.2 Table 3).
/// Prefixes with a shared root (e.g. `https://www.` vs `https://`) are checked
/// longest-match first. If no prefix matches, the URL is stored verbatim with
/// code 0x00 and [`SdmUrlConfig::prefix_len`] is `0`.
///
/// | Prefix                       | Code |
/// |------------------------------|------|
/// | `http://www.`                | 0x01 |
/// | `https://www.`               | 0x02 |
/// | `http://`                    | 0x03 |
/// | `https://`                   | 0x04 |
/// | `tel:`                       | 0x05 |
/// | `mailto:`                    | 0x06 |
/// | `ftp://anonymous:anonymous@` | 0x07 |
/// | `ftp://ftp.`                 | 0x08 |
/// | `ftps://`                    | 0x09 |
/// | `sftp://`                    | 0x0A |
/// | `smb://`                     | 0x0B |
/// | `nfs://`                     | 0x0C |
/// | `ftp://`                     | 0x0D |
/// | `dav://`                     | 0x0E |
/// | `news:`                      | 0x0F |
/// | `telnet://`                  | 0x10 |
/// | `imap:`                      | 0x11 |
/// | `rtsp://`                    | 0x12 |
/// | `urn:`                       | 0x13 |
/// | `pop:`                       | 0x14 |
/// | `sip:`                       | 0x15 |
/// | `sips:`                      | 0x16 |
/// | `tftp:`                      | 0x17 |
/// | `btspp://`                   | 0x18 |
/// | `btl2cap://`                 | 0x19 |
/// | `btgoep://`                  | 0x1A |
/// | `tcpobex://`                 | 0x1B |
/// | `irdaobex://`                | 0x1C |
/// | `file://`                    | 0x1D |
/// | `urn:epc:id:`                | 0x1E |
/// | `urn:epc:tag:`               | 0x1F |
/// | `urn:epc:pat:`               | 0x20 |
/// | `urn:epc:raw:`               | 0x21 |
/// | `urn:epc:`                   | 0x22 |
/// | `urn:nfc:`                   | 0x23 |
///
/// ## Consequences for server-side verification
///
/// SDM offsets in [`SdmUrlConfig::sdm_settings`] are absolute byte positions
/// within [`SdmUrlConfig::ndef_bytes`]. An NFC reader reconstructs the full URL
/// by prepending the prefix string to the abbreviated body before following it.
/// On the server, which receives the full URL, use this formula to convert an
/// NDEF byte offset to a URL character index:
///
/// ```text
/// url_char_index = ndef_byte_offset - offset + prefix_len
/// ```
///
/// where [`offset`](`SdmUrlConfig::offset`) is always `7`. For example, with
/// `prefix_len = 8` (`https://`) and an NDEF MAC offset of `57`:
/// `url_char_index = 57 - 7 + 8 = 58`.
///
/// # Example
///
/// ```
/// use ntag424::sdm::{sdm_url_config, SdmUrlOptions};
/// use ntag424::types::file_settings::CryptoMode;
/// use ntag424::types::KeyNumber;
///
/// let opts = SdmUrlOptions {
///     picc_key: KeyNumber::Key2,
///     mac_key: KeyNumber::Key2,
///     ..SdmUrlOptions::default()
/// };
/// let plan = sdm_url_config(
///     "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
///     CryptoMode::Aes,
///     opts,
/// ).unwrap();
///
/// let _ = plan.ndef_bytes;
/// let _ = plan.sdm_settings;
/// ```
pub fn sdm_url_config(
    url: &str,
    mode: CryptoMode,
    opts: SdmUrlOptions,
) -> Result<SdmUrlConfig, SdmUrlError> {
    match build_sdm_ndef_plan_core::<DEFAULT_CONST_PLAN_CAPACITY>(url, mode, opts) {
        Ok(plan) => Ok(SdmUrlConfig {
            ndef_bytes: plan.ndef_bytes.as_slice().to_vec(),
            sdm_settings: plan.sdm_settings,
            offset: URI_AT as usize,
            prefix_len: plan.prefix_len,
            prefix_code: plan.prefix_code,
        }),
        Err(err) => Err(map_runtime_error(url, err)),
    }
}

#[doc(hidden)]
pub const fn build_sdm_ndef_plan_const<const N: usize>(
    url: &str,
    mode: CryptoMode,
    opts: SdmUrlOptions,
) -> ConstSdmNdefPlan<N> {
    match build_sdm_ndef_plan_core::<N>(url, mode, opts) {
        Ok(plan) => plan,
        Err(err) => panic_on_const_error(err),
    }
}

// ---------------------------------------------------------------------------
// Shared core
// ---------------------------------------------------------------------------

const fn build_sdm_ndef_plan_core<const N: usize>(
    url: &str,
    mode: CryptoMode,
    opts: SdmUrlOptions,
) -> Result<ConstSdmNdefPlan<N>, TemplateCoreError> {
    let bytes = url.as_bytes();
    let (prefix_code, abbrev_start) = detect_uri_prefix(bytes);
    let parsed = match parse_template::<N>(bytes, abbrev_start, mode) {
        Ok(parsed) => parsed,
        Err(err) => return Err(err),
    };

    let payload_len = 1 + parsed.uri_content.len();
    if payload_len > 255 {
        return Err(TemplateCoreError::FileTooLong {
            got: 2 + 4 + payload_len,
            max: opts.max_file_size,
        });
    }
    let ndef_msg_len = 4 + payload_len;
    let total_len = 2 + ndef_msg_len;
    if total_len > opts.max_file_size as usize {
        return Err(TemplateCoreError::FileTooLong {
            got: total_len,
            max: opts.max_file_size,
        });
    }

    let mut ndef_bytes = ConstNdefBytes::<N>::new();
    macro_rules! try_push {
        ($byte:expr, $($rest:expr),*) => {
            try_push!($byte);
            try_push!($($rest),*);
        };
        ($byte:expr) => {
            match ndef_bytes.push($byte) {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
        };
    }
    try_push!(
        ((ndef_msg_len as u16) >> 8) as u8,
        (ndef_msg_len as u16) as u8,
        0xD1,
        0x01,
        payload_len as u8,
        0x55,
        prefix_code
    );
    match ndef_bytes.extend_bytes(&parsed.uri_content.bytes, 0, parsed.uri_content.len()) {
        Ok(()) => {}
        Err(err) => return Err(err),
    }

    macro_rules! try_offset {
        (Some($opt:expr), $name:expr) => {
            match $opt {
                Some(opt) => Some(try_offset!(opt, $name)),
                None => None,
            }
        };
        ($opt:expr, $name:expr) => {
            match Offset::new($opt) {
                Ok(o) => o,
                Err(_) => {
                    return Err(TemplateCoreError::FileSettings(concat!(
                        $name,
                        " out of range"
                    )))
                }
            }
        };
    }

    // Build picc_data
    let picc_data = if let Some((picc_offset, content)) = parsed.picc {
        let offset = try_offset!(picc_offset, "picc_offset");
        let enc_content = match content {
            PiccContent::Uid => EncryptedContent::Uid,
            PiccContent::Ctr => EncryptedContent::RCtr(ReadCtrFeatures {
                limit: None,
                ret_access: opts.ctr_ret,
            }),
            PiccContent::Both => EncryptedContent::Both(ReadCtrFeatures {
                limit: None,
                ret_access: opts.ctr_ret,
            }),
        };
        PiccData::Encrypted {
            key: opts.picc_key,
            offset,
            content: enc_content,
        }
    } else {
        let uid_offset = try_offset!(Some(parsed.uid_offset), "uid_offset");
        let ctr_offset = try_offset!(Some(parsed.ctr_offset), "ctr_offset");
        match (uid_offset, ctr_offset) {
            (Some(uid), Some(ctr)) => PiccData::Plain(PlainMirror::Both {
                uid,
                read_ctr: ReadCtrMirror {
                    offset: ctr,
                    features: ReadCtrFeatures {
                        limit: None,
                        ret_access: opts.ctr_ret,
                    },
                },
            }),
            (Some(uid), None) => PiccData::Plain(PlainMirror::Uid { uid }),
            (None, Some(ctr)) => PiccData::Plain(PlainMirror::RCtr {
                read_ctr: ReadCtrMirror {
                    offset: ctr,
                    features: ReadCtrFeatures {
                        limit: None,
                        ret_access: opts.ctr_ret,
                    },
                },
            }),
            (None, None) => PiccData::None,
        }
    };

    let window = MacWindow {
        input: try_offset!(parsed.mac_input, "mac_input"),
        mac: try_offset!(parsed.mac_offset, "mac_offset"),
    };

    // Build file_read
    let file_read = if let Some((enc_start, enc_end)) = parsed.enc_range {
        let start = try_offset!(enc_start, "enc_start");
        let length = match EncLength::new(enc_end - enc_start) {
            Ok(l) => l,
            Err(_) => return Err(TemplateCoreError::FileSettings("enc_length invalid")),
        };
        Some(FileRead::MacAndEnc {
            key: opts.mac_key,
            window,
            enc: EncFileData { start, length },
        })
    } else {
        Some(FileRead::MacOnly {
            key: opts.mac_key,
            window,
        })
    };

    let tamper_status = try_offset!(Some(parsed.tt_offset), "tt_offset");
    let sdm_settings = match Sdm::try_new(picc_data, file_read, tamper_status, mode) {
        Ok(sdm) => sdm,
        Err(FileSettingsError::MacInputAfterMac) => {
            return Err(TemplateCoreError::FileSettings("mac_input > mac"));
        }
        Err(FileSettingsError::EncOutsideMacWindow) => {
            return Err(TemplateCoreError::FileSettings("enc outside mac window"));
        }
        Err(FileSettingsError::EncRequiresBothMirrors) => {
            return Err(TemplateCoreError::EncFileDataRequiresUidAndCtr);
        }
        Err(_) => return Err(TemplateCoreError::FileSettings("sdm_settings")),
    };

    Ok(ConstSdmNdefPlan {
        ndef_bytes,
        sdm_settings,
        prefix_len: abbrev_start,
        prefix_code,
    })
}

const fn parse_template<const N: usize>(
    url: &[u8],
    start: usize,
    mode: CryptoMode,
) -> Result<ParsedTemplate<N>, TemplateCoreError> {
    let mut uri_content = ConstNdefBytes::<N>::new();
    let mut uid_offset = None;
    let mut ctr_offset = None;
    let mut picc = None;
    let mut tt_offset = None;
    let mut mac_offset = None;
    let mut saw_mac_start = false;
    let mut mac_start = None;
    let mut in_enc_range = false;
    let mut enc_range_start = None;
    let mut enc_range_end = None;

    let mut i = start;
    while i < url.len() {
        let b = url[i];

        if in_enc_range {
            if b == b']' {
                enc_range_end = Some(current_file_offset_len(uri_content.len()));
                in_enc_range = false;
                i += 1;
                continue;
            }
            if b == b'[' && i + 1 < url.len() && url[i + 1] == b'[' {
                return Err(TemplateCoreError::NestedRange("[[ inside [...]"));
            }
            if b == b'[' {
                return Err(TemplateCoreError::NestedRange("[...]"));
            }
            if b == b'\\' {
                let width = match escaped_width(url, i) {
                    Ok(width) => width,
                    Err(err) => return Err(err),
                };
                match uri_content.push_zeroes(width) {
                    Ok(()) => {}
                    Err(err) => return Err(err),
                }
                i += 1 + width;
                continue;
            }
            if b == b'{' {
                let (placeholder, consumed, display, _start, _end) = match parse_placeholder(url, i)
                {
                    Ok(parsed) => parsed,
                    Err(err) => return Err(err),
                };
                match placeholder {
                    Placeholder::Tt => {
                        tt_offset = match set_once(
                            tt_offset,
                            current_file_offset_len(uri_content.len()),
                            "{tt}",
                        ) {
                            Ok(value) => value,
                            Err(err) => return Err(err),
                        };
                        match uri_content.push_zeroes(placeholder_fill_len(placeholder, mode)) {
                            Ok(()) => {}
                            Err(err) => return Err(err),
                        }
                    }
                    _ => return Err(TemplateCoreError::PlaceholderInEncRange(display)),
                }
                i += consumed;
                continue;
            }

            let width = utf8_char_width(b);
            match uri_content.push_zeroes(width) {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
            i += width;
            continue;
        }

        if b == b'[' && i + 1 < url.len() && url[i + 1] == b'[' {
            if saw_mac_start {
                return Err(TemplateCoreError::DuplicateRange("[["));
            }
            saw_mac_start = true;
            mac_start = Some(current_file_offset_len(uri_content.len()));
            i += 2;
            continue;
        }
        if b == b'[' {
            if enc_range_start.is_some() {
                return Err(TemplateCoreError::DuplicateRange("[...]"));
            }
            in_enc_range = true;
            enc_range_start = Some(current_file_offset_len(uri_content.len()));
            i += 1;
            continue;
        }
        if b == b']' {
            return Err(TemplateCoreError::UnexpectedMarker("]"));
        }
        if b == b'\\' {
            let width = match escaped_width(url, i) {
                Ok(width) => width,
                Err(err) => return Err(err),
            };
            match uri_content.extend_bytes(url, i + 1, width) {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
            i += 1 + width;
            continue;
        }
        if b == b'{' {
            let (placeholder, consumed, display, _start, _end) = match parse_placeholder(url, i) {
                Ok(parsed) => parsed,
                Err(err) => return Err(err),
            };
            let offset = current_file_offset_len(uri_content.len());
            match placeholder {
                Placeholder::Uid => {
                    uid_offset = match set_once(uid_offset, offset, display) {
                        Ok(value) => value,
                        Err(err) => return Err(err),
                    };
                }
                Placeholder::Ctr => {
                    ctr_offset = match set_once(ctr_offset, offset, display) {
                        Ok(value) => value,
                        Err(err) => return Err(err),
                    };
                }
                Placeholder::Picc(content) => {
                    picc = match set_once(picc, (offset, content), "{picc}") {
                        Ok(value) => value,
                        Err(err) => return Err(err),
                    };
                }
                Placeholder::Tt => {
                    tt_offset = match set_once(tt_offset, offset, display) {
                        Ok(value) => value,
                        Err(err) => return Err(err),
                    };
                }
                Placeholder::Mac => {
                    mac_offset = match set_once(mac_offset, offset, display) {
                        Ok(value) => value,
                        Err(err) => return Err(err),
                    };
                }
            }
            match uri_content.push_zeroes(placeholder_fill_len(placeholder, mode)) {
                Ok(()) => {}
                Err(err) => return Err(err),
            }
            i += consumed;
            continue;
        }

        let width = utf8_char_width(b);
        match uri_content.extend_bytes(url, i, width) {
            Ok(()) => {}
            Err(err) => return Err(err),
        }
        i += width;
    }

    if in_enc_range {
        return Err(TemplateCoreError::Unterminated("[...]"));
    }

    let mac_offset = match mac_offset {
        Some(offset) => offset,
        None => return Err(TemplateCoreError::MissingMac),
    };
    if picc.is_some() && (uid_offset.is_some() || ctr_offset.is_some()) {
        return Err(TemplateCoreError::PiccWithPlainMirrors);
    }
    if picc.is_none() && uid_offset.is_none() && ctr_offset.is_none() && tt_offset.is_none() {
        return Err(TemplateCoreError::NoMirror);
    }

    let includes_uid = match picc {
        Some((_, content)) => picc_content_includes_uid(content),
        None => uid_offset.is_some(),
    };
    let includes_ctr = match picc {
        Some((_, content)) => picc_content_includes_ctr(content),
        None => ctr_offset.is_some(),
    };

    let enc_range = if enc_range_start.is_some() || enc_range_end.is_some() {
        let start = match enc_range_start {
            Some(start) => start,
            None => return Err(TemplateCoreError::Unterminated("[...]")),
        };
        let end = match enc_range_end {
            Some(end) => end,
            None => return Err(TemplateCoreError::Unterminated("[...]")),
        };
        let len = end.saturating_sub(start);
        if len == 0 || len % 32 != 0 {
            return Err(TemplateCoreError::InvalidEncRangeLength(len));
        }
        if !includes_uid || !includes_ctr {
            return Err(TemplateCoreError::EncFileDataRequiresUidAndCtr);
        }
        Some((start, end))
    } else {
        None
    };

    let mac_input = match mac_start {
        Some(start) => start,
        None => URI_AT,
    };
    if mac_input > mac_offset {
        return Err(TemplateCoreError::MacStartAfterMac);
    }

    Ok(ParsedTemplate {
        uri_content,
        uid_offset,
        ctr_offset,
        picc,
        tt_offset,
        mac_offset,
        mac_input,
        enc_range,
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const fn placeholder_fill_len(placeholder: Placeholder, mode: CryptoMode) -> usize {
    match placeholder {
        Placeholder::Uid => 14,
        Placeholder::Ctr => 6,
        Placeholder::Tt => 2,
        Placeholder::Mac => 16,
        Placeholder::Picc(_) => mode.picc_blob_ascii_len() as usize,
    }
}

const fn picc_content_includes_uid(content: PiccContent) -> bool {
    matches!(content, PiccContent::Uid | PiccContent::Both)
}

const fn picc_content_includes_ctr(content: PiccContent) -> bool {
    matches!(content, PiccContent::Ctr | PiccContent::Both)
}

const NDEF_URI_PREFIXES: &[(u8, &[u8])] = &[
    (0x01, b"http://www.".as_slice()),
    (0x02, b"https://www.".as_slice()),
    (0x03, b"http://".as_slice()),
    (0x04, b"https://".as_slice()),
    (0x05, b"tel:".as_slice()),
    (0x06, b"mailto:".as_slice()),
    (0x07, b"ftp://anonymous:anonymous@".as_slice()),
    (0x08, b"ftp://ftp.".as_slice()),
    (0x09, b"ftps://".as_slice()),
    (0x0A, b"sftp://".as_slice()),
    (0x0B, b"smb://".as_slice()),
    (0x0C, b"nfs://".as_slice()),
    (0x0D, b"ftp://".as_slice()),
    (0x0E, b"dav://".as_slice()),
    (0x0F, b"news:".as_slice()),
    (0x10, b"telnet://".as_slice()),
    (0x11, b"imap:".as_slice()),
    (0x12, b"rtsp://".as_slice()),
    (0x13, b"urn:".as_slice()),
    (0x14, b"pop:".as_slice()),
    (0x15, b"sip:".as_slice()),
    (0x16, b"sips:".as_slice()),
    (0x17, b"tftp:".as_slice()),
    (0x18, b"btspp://".as_slice()),
    (0x19, b"btl2cap://".as_slice()),
    (0x1A, b"btgoep://".as_slice()),
    (0x1B, b"tcpobex://".as_slice()),
    (0x1C, b"irdaobex://".as_slice()),
    (0x1D, b"file://".as_slice()),
    (0x1E, b"urn:epc:id:".as_slice()),
    (0x1F, b"urn:epc:tag:".as_slice()),
    (0x20, b"urn:epc:pat:".as_slice()),
    (0x21, b"urn:epc:raw:".as_slice()),
    (0x22, b"urn:epc:".as_slice()),
    (0x23, b"urn:nfc:".as_slice()),
];

#[cfg(feature = "alloc")]
type UriString = alloc::string::String;
#[cfg(not(feature = "alloc"))]
type UriString = arrayvec::ArrayString<256>;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("missing {{mac}} placeholder")]
    InvalidHeader,
    #[error(
        "NDEF message length field does not match actual length: expected {expected}, actual {actual}"
    )]
    SizeMismatch { expected: usize, actual: usize },
    #[error("NDEF URI prefix code is not recognized")]
    UnknownPrefixCode(u8),
    #[error("NDEF record length does not match expected payload length")]
    PayloadSizeMismatch { expected: usize, actual: usize },
    #[error("NDEF payload is not valid UTF-8: {0}")]
    Encoding(#[from] core::str::Utf8Error),
}

/// Parse NDEF bytes from the tag back into a full URL string.
pub fn parse_ndef_uri(ndef_bytes: &[u8]) -> Result<impl AsRef<str>, ParseError> {
    if ndef_bytes.len() < 7
        || ndef_bytes[2] != 0xD1
        || ndef_bytes[3] != 0x01
        || ndef_bytes[5] != 0x55
    {
        return Err(ParseError::InvalidHeader);
    }
    let size = ((ndef_bytes[0] as usize) << 8) | (ndef_bytes[1] as usize);
    if size + 2 > ndef_bytes.len() {
        return Err(ParseError::SizeMismatch {
            expected: size + 2,
            actual: ndef_bytes.len(),
        });
    }
    let ndef_bytes = &ndef_bytes[..size + 2];
    let payload_len = ndef_bytes[4];
    let prefix_code = ndef_bytes[6];
    let prefix = if prefix_code == 0x00 {
        b"".as_slice()
    } else if let Some((_, prefix)) = NDEF_URI_PREFIXES
        .iter()
        .find(|(code, _)| *code == prefix_code)
    {
        prefix
    } else {
        return Err(ParseError::UnknownPrefixCode(prefix_code));
    };

    if ndef_bytes.len() != 2 + 4 + payload_len as usize {
        return Err(ParseError::PayloadSizeMismatch {
            expected: 2 + 4 + payload_len as usize,
            actual: ndef_bytes.len(),
        });
    }

    let mut url = {
        #[cfg(feature = "alloc")]
        {
            UriString::with_capacity(prefix.len() + payload_len as usize - 1)
        }
        #[cfg(not(feature = "alloc"))]
        {
            UriString::new()
        }
    };
    url.push_str(core::str::from_utf8(prefix)?);
    url.push_str(core::str::from_utf8(&ndef_bytes[7..])?);
    Ok(url)
}

const fn detect_uri_prefix(url: &[u8]) -> (u8, usize) {
    let mut i = 0;
    while i < NDEF_URI_PREFIXES.len() {
        let (code, prefix) = NDEF_URI_PREFIXES[i];
        if bytes_eq_at(url, 0, prefix) {
            return (code, prefix.len());
        }
        i += 1;
    }
    (0x00, 0)
}

const fn bytes_eq_at(haystack: &[u8], start: usize, needle: &[u8]) -> bool {
    if haystack.len() < start + needle.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if haystack[start + i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn utf8_char_width(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else {
        4
    }
}

const fn escaped_width(url: &[u8], backslash: usize) -> Result<usize, TemplateCoreError> {
    if backslash + 1 >= url.len() {
        return Err(TemplateCoreError::Unterminated("escape sequence"));
    }
    Ok(utf8_char_width(url[backslash + 1]))
}

const fn current_file_offset_len(uri_len: usize) -> u32 {
    URI_AT + uri_len as u32
}

const fn parse_placeholder(
    url: &[u8],
    start: usize,
) -> Result<(Placeholder, usize, &'static str, usize, usize), TemplateCoreError> {
    let mut end = start + 1;
    while end < url.len() {
        if url[end] == b'}' {
            let spec_start = start + 1;
            let spec_len = end - spec_start;
            let placeholder = if bytes_match(url, spec_start, spec_len, b"uid") {
                (Placeholder::Uid, "{uid}")
            } else if bytes_match(url, spec_start, spec_len, b"ctr") {
                (Placeholder::Ctr, "{ctr}")
            } else if bytes_match(url, spec_start, spec_len, b"tt") {
                (Placeholder::Tt, "{tt}")
            } else if bytes_match(url, spec_start, spec_len, b"mac") {
                (Placeholder::Mac, "{mac}")
            } else if bytes_match(url, spec_start, spec_len, b"picc") {
                (Placeholder::Picc(PiccContent::Both), "{picc}")
            } else if bytes_match(url, spec_start, spec_len, b"picc:uid") {
                (Placeholder::Picc(PiccContent::Uid), "{picc}")
            } else if bytes_match(url, spec_start, spec_len, b"picc:ctr") {
                (Placeholder::Picc(PiccContent::Ctr), "{picc}")
            } else if bytes_match(url, spec_start, spec_len, b"picc:uid+ctr")
                || bytes_match(url, spec_start, spec_len, b"picc:ctr+uid")
            {
                (Placeholder::Picc(PiccContent::Both), "{picc}")
            } else {
                return Err(TemplateCoreError::InvalidPlaceholder {
                    start,
                    end: end + 1,
                });
            };
            return Ok((
                placeholder.0,
                end + 1 - start,
                placeholder.1,
                start,
                end + 1,
            ));
        }
        end += 1;
    }
    Err(TemplateCoreError::Unterminated("placeholder"))
}

const fn bytes_match(haystack: &[u8], start: usize, len: usize, needle: &[u8]) -> bool {
    len == needle.len() && bytes_eq_at(haystack, start, needle)
}

const fn set_once<T: Copy>(
    slot: Option<T>,
    value: T,
    name: &'static str,
) -> Result<Option<T>, TemplateCoreError> {
    if slot.is_some() {
        return Err(TemplateCoreError::DuplicatePlaceholder(name));
    }
    Ok(Some(value))
}

#[cfg(feature = "alloc")]
fn map_runtime_error(url: &str, err: TemplateCoreError) -> SdmUrlError {
    match err {
        TemplateCoreError::MissingMac => SdmUrlError::MissingMac,
        TemplateCoreError::PiccWithPlainMirrors => SdmUrlError::PiccWithPlainMirrors,
        TemplateCoreError::NoMirror => SdmUrlError::NoMirror,
        TemplateCoreError::DuplicatePlaceholder(name) => SdmUrlError::DuplicatePlaceholder(name),
        TemplateCoreError::EncFileDataRequiresUidAndCtr => {
            SdmUrlError::EncFileDataRequiresUidAndCtr
        }
        TemplateCoreError::InvalidEncRangeLength(len) => SdmUrlError::InvalidEncRangeLength(len),
        TemplateCoreError::InvalidPlaceholder { start, end } => {
            SdmUrlError::InvalidPlaceholder(url[start..end].to_owned())
        }
        TemplateCoreError::Unterminated(name) => SdmUrlError::Unterminated(name),
        TemplateCoreError::UnexpectedMarker(name) => SdmUrlError::UnexpectedMarker(name),
        TemplateCoreError::DuplicateRange(name) => SdmUrlError::DuplicateRange(name),
        TemplateCoreError::PlaceholderInEncRange(name) => SdmUrlError::PlaceholderInEncRange(name),
        TemplateCoreError::NestedRange(name) => SdmUrlError::NestedRange(name),
        TemplateCoreError::MacStartAfterMac => SdmUrlError::MacStartAfterMac,
        TemplateCoreError::OutputBufferTooSmall { needed, capacity } => SdmUrlError::FileTooLong {
            got: needed,
            max: capacity as u16,
        },
        TemplateCoreError::FileTooLong { got, max } => SdmUrlError::FileTooLong { got, max },
        TemplateCoreError::FileSettings(_) => {
            SdmUrlError::FileSettings(FileSettingsError::MacInputAfterMac)
        }
    }
}

const fn panic_on_const_error(err: TemplateCoreError) -> ! {
    match err {
        TemplateCoreError::MissingMac => panic!("SDM URL template is missing {{mac}}"),
        TemplateCoreError::PiccWithPlainMirrors => {
            panic!("SDM URL template mixes {{picc...}} with {{uid}}/{{ctr}}")
        }
        TemplateCoreError::NoMirror => {
            panic!("SDM URL template has no dynamic mirrors")
        }
        TemplateCoreError::DuplicatePlaceholder(_) => {
            panic!("SDM URL template contains a duplicate placeholder")
        }
        TemplateCoreError::EncFileDataRequiresUidAndCtr => {
            panic!("SDM encrypted file data requires UID and SDMReadCtr mirroring")
        }
        TemplateCoreError::InvalidEncRangeLength(_) => {
            panic!("SDM encrypted file data range must be a positive multiple of 32 bytes")
        }
        TemplateCoreError::InvalidPlaceholder { .. } => {
            panic!("SDM URL template contains an invalid placeholder")
        }
        TemplateCoreError::Unterminated(_) => {
            panic!("SDM URL template contains an unterminated marker")
        }
        TemplateCoreError::UnexpectedMarker(_) => {
            panic!("SDM URL template contains an unexpected marker")
        }
        TemplateCoreError::DuplicateRange(_) => {
            panic!("SDM URL template contains a duplicate range marker")
        }
        TemplateCoreError::PlaceholderInEncRange(_) => {
            panic!("SDM URL template contains a forbidden placeholder inside [...]")
        }
        TemplateCoreError::NestedRange(_) => {
            panic!("SDM URL template contains a nested range")
        }
        TemplateCoreError::MacStartAfterMac => {
            panic!("SDM URL [[ marker must appear before {{mac}}")
        }
        TemplateCoreError::OutputBufferTooSmall { .. } => {
            panic!("SDM const output buffer is too small")
        }
        TemplateCoreError::FileTooLong { .. } => {
            panic!("SDM URL template produces an NDEF file that is too long")
        }
        TemplateCoreError::FileSettings(_) => {
            panic!("SDM URL template produced inconsistent SDM settings")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::file_settings::{
        CtrRetAccess, EncryptedContent, FileRead, Offset, PiccData, PlainMirror, ReadCtrFeatures,
    };

    fn key0_opts() -> SdmUrlOptions {
        SdmUrlOptions {
            picc_key: KeyNumber::Key0,
            mac_key: KeyNumber::Key0,
            ctr_ret: CtrRetAccess::NoAccess,
            max_file_size: 256,
        }
    }

    fn file_read(plan: &SdmUrlConfig) -> FileRead {
        plan.sdm_settings.file_read().unwrap()
    }

    #[test]
    fn picc_mac_aes() {
        let plan = sdm_url_config(
            "https://example.com/?p={picc}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(
            plan.sdm_settings.picc_data(),
            PiccData::Encrypted {
                key: KeyNumber::Key0,
                offset: Offset::new(URI_AT + 15).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                }),
            }
        );
        let fr = file_read(&plan);
        assert_eq!(fr.key(), KeyNumber::Key0);
        assert_eq!(fr.window().input.get(), URI_AT);
        assert_eq!(fr.window().mac.get(), URI_AT + 24 + 26);
        assert!(fr.enc().is_none());
        assert_eq!(plan.sdm_settings.tamper_status(), None);
        assert_eq!(plan.ndef_bytes[2], 0xD1);
        assert_eq!(plan.ndef_bytes[3], 0x01);
        assert_eq!(plan.ndef_bytes[5], 0x55);
        assert_eq!(plan.ndef_bytes[6], 0x04);
    }

    #[test]
    fn picc_uid_only_uses_new_syntax() {
        let plan = sdm_url_config(
            "https://example.com/?p={picc:uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(
            plan.sdm_settings.picc_data(),
            PiccData::Encrypted {
                key: KeyNumber::Key0,
                offset: Offset::new(URI_AT + 15).unwrap(),
                content: EncryptedContent::Uid,
            }
        );
    }

    #[test]
    fn picc_mac_lrp() {
        let plan = sdm_url_config(
            "https://example.com/?p={picc}&m={mac}",
            CryptoMode::Lrp,
            key0_opts(),
        )
        .unwrap();

        let picc_start = match plan.sdm_settings.picc_data() {
            PiccData::Encrypted { offset, .. } => offset.get() as usize,
            _ => unreachable!(),
        };
        for &b in &plan.ndef_bytes[picc_start..picc_start + 48] {
            assert_eq!(b, b'0');
        }
    }

    #[test]
    fn uid_ctr_mac() {
        let plan = sdm_url_config(
            "https://example.com/?u={uid}&n={ctr}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert!(matches!(
            plan.sdm_settings.picc_data(),
            PiccData::Plain(PlainMirror::Both { .. })
        ));
        assert!(plan.sdm_settings.file_read().is_some());
    }

    #[test]
    fn query_only_url_mac_input() {
        let plan = sdm_url_config(
            "https://example.com?p={picc}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(file_read(&plan).window().input.get(), URI_AT);
    }

    #[test]
    fn explicit_mac_start_overrides_default() {
        let plan = sdm_url_config(
            "https://example.com/?u={uid}&[[x={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let fr = file_read(&plan);
        assert_eq!(fr.window().input.get(), URI_AT + 30);
        assert_eq!(fr.window().mac.get(), URI_AT + 32);
        assert_eq!(
            &plan.ndef_bytes[fr.window().input.get() as usize..fr.window().mac.get() as usize],
            b"x="
        );
    }

    #[test]
    fn encrypted_range_sets_sdm_enc_file_data() {
        let plan = sdm_url_config(
            "https://example.com/?u={uid}&c={ctr}&e=[................................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let fr = file_read(&plan);
        let enc = fr.enc().unwrap();
        let start = enc.start.get() as usize;
        let len = enc.length.get() as usize;
        assert_eq!(len, 32);
        assert!(
            plan.ndef_bytes[start..start + len]
                .iter()
                .all(|&b| b == b'0')
        );
    }

    #[test]
    fn tt_mirror_is_supported() {
        let plan = sdm_url_config(
            "https://example.com/?u={uid}&tt={tt}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let tt_offset = plan.sdm_settings.tamper_status().unwrap().get() as usize;
        assert_eq!(&plan.ndef_bytes[tt_offset..tt_offset + 2], b"00");
    }

    #[test]
    fn tt_only_template_forces_counter_access_off_without_ctr_mirror() {
        let plan = sdm_url_config(
            "https://example.com/?tt={tt}&m={mac}",
            CryptoMode::Aes,
            SdmUrlOptions {
                ctr_ret: CtrRetAccess::Key(KeyNumber::Key0),
                ..key0_opts()
            },
        )
        .unwrap();

        assert_eq!(plan.sdm_settings.picc_data(), PiccData::None);
        assert_eq!(
            plan.sdm_settings.tamper_status(),
            Some(Offset::new(URI_AT + 16).unwrap())
        );
    }

    #[test]
    fn tt_can_live_inside_enc_range() {
        let plan = sdm_url_config(
            "https://example.com/?u={uid}&c={ctr}&[[e=[............{tt}..................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let fr = file_read(&plan);
        let enc = fr.enc().unwrap();
        let enc_start = enc.start.get();
        let enc_end = enc_start + enc.length.get();
        let tt_offset = plan.sdm_settings.tamper_status().unwrap().get();
        assert!(tt_offset >= enc_start);
        assert!(tt_offset + 2 <= enc_end);
        assert_eq!(fr.window().input.get(), URI_AT + 39);
    }

    #[test]
    fn escapes_render_literal_syntax() {
        let plan = sdm_url_config(
            r"https://example.com/?lit=\{uid\}\[\]&u={uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert!(
            core::str::from_utf8(&plan.ndef_bytes[7..])
                .unwrap()
                .contains("?lit={uid}[]&u=")
        );
    }

    #[test]
    fn const_builder_matches_runtime() {
        const CONST_PLAN: ConstSdmNdefPlan<256> = build_sdm_ndef_plan_const(
            "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
            CryptoMode::Aes,
            SdmUrlOptions {
                picc_key: KeyNumber::Key0,
                mac_key: KeyNumber::Key0,
                ctr_ret: CtrRetAccess::NoAccess,
                max_file_size: 256,
            },
        );

        let runtime = sdm_url_config(
            "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(CONST_PLAN.sdm_settings, runtime.sdm_settings);
        assert_eq!(
            CONST_PLAN.ndef_bytes.as_slice(),
            runtime.ndef_bytes.as_slice()
        );
    }

    #[test]
    fn macro_returns_static_refs() {
        let (ndef, settings) = crate::sdm_url_config!(
            "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
            CryptoMode::Aes
        );

        let runtime = sdm_url_config(
            "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
            CryptoMode::Aes,
            SdmUrlOptions::new(),
        )
        .unwrap();

        assert_eq!(ndef, runtime.ndef_bytes.as_slice());
        assert_eq!(settings, &runtime.sdm_settings);
    }

    #[test]
    fn error_missing_mac() {
        let err = sdm_url_config(
            "https://example.com/?p={picc}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::MissingMac);
    }

    #[test]
    fn error_picc_with_uid() {
        let err = sdm_url_config(
            "https://example.com/?p={picc}&u={uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::PiccWithPlainMirrors);
    }

    #[test]
    fn error_no_mirror() {
        let err = sdm_url_config("https://example.com/?m={mac}", CryptoMode::Aes, key0_opts())
            .unwrap_err();
        assert_eq!(err, SdmUrlError::NoMirror);
    }

    #[test]
    fn error_duplicate_picc() {
        let err = sdm_url_config(
            "https://example.com/?p={picc}&q={picc:uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::DuplicatePlaceholder("{picc}"));
    }

    #[test]
    fn error_uid_inside_encrypted_range() {
        let err = sdm_url_config(
            "https://example.com/?u={uid}&c={ctr}&e=[xx{uid}xxxxxxxxxxxxxxxxxxxx]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::PlaceholderInEncRange("{uid}"));
    }

    #[test]
    fn error_enc_range_requires_uid_and_ctr() {
        let err = sdm_url_config(
            "https://example.com/?u={uid}&e=[................................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::EncFileDataRequiresUidAndCtr);
    }

    #[test]
    fn error_mac_start_after_mac() {
        let err = sdm_url_config(
            "https://example.com/?u={uid}&m={mac}[[x=",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::MacStartAfterMac);
    }

    #[test]
    fn error_file_too_long() {
        let long_path = "a".repeat(240);
        let url = alloc::format!("https://example.com/{long_path}?p={{picc}}&m={{mac}}");
        let err = sdm_url_config(&url, CryptoMode::Aes, key0_opts()).unwrap_err();
        assert!(matches!(err, SdmUrlError::FileTooLong { .. }));
    }

    // ---------------------------------------------------------------------------
    // parse_ndef_uri
    // ---------------------------------------------------------------------------

    fn make_ndef_uri(prefix_code: u8, uri_content: &[u8]) -> alloc::vec::Vec<u8> {
        let payload_len = 1 + uri_content.len();
        let ndef_msg_len = 4 + payload_len;
        let mut bytes = alloc::vec![
            (ndef_msg_len >> 8) as u8,
            ndef_msg_len as u8,
            0xD1,
            0x01,
            payload_len as u8,
            0x55,
            prefix_code,
        ];
        bytes.extend_from_slice(uri_content);
        bytes
    }

    #[test]
    fn parse_ndef_uri_no_prefix() {
        let bytes = make_ndef_uri(0x00, b"example.com");
        assert_eq!(parse_ndef_uri(&bytes).unwrap().as_ref(), "example.com");
    }

    #[test]
    fn parse_ndef_uri_https_prefix() {
        let bytes = make_ndef_uri(0x04, b"example.com/path");
        assert_eq!(
            parse_ndef_uri(&bytes).unwrap().as_ref(),
            "https://example.com/path"
        );
    }

    #[test]
    fn parse_ndef_uri_https_www_prefix() {
        let bytes = make_ndef_uri(0x02, b"example.com");
        assert_eq!(
            parse_ndef_uri(&bytes).unwrap().as_ref(),
            "https://www.example.com"
        );
    }

    #[test]
    fn parse_ndef_uri_empty_content() {
        // payload_len = 1 (prefix code only), no URI content
        let bytes = make_ndef_uri(0x04, b"");
        assert_eq!(parse_ndef_uri(&bytes).unwrap().as_ref(), "https://");
    }

    #[test]
    fn parse_ndef_uri_unknown_prefix_returns_none() {
        let bytes = make_ndef_uri(0xFF, b"example.com");
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_too_short_returns_none() {
        assert!(parse_ndef_uri(&[]).is_err());
        assert!(parse_ndef_uri(&[0x00, 0x05, 0xD1, 0x01, 0x01, 0x55]).is_err()); // 6 bytes
    }

    #[test]
    fn parse_ndef_uri_bad_record_header_returns_none() {
        let mut bytes = make_ndef_uri(0x04, b"example.com");
        bytes[2] = 0xC1; // not 0xD1
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_bad_type_length_returns_none() {
        let mut bytes = make_ndef_uri(0x04, b"example.com");
        bytes[3] = 0x02; // not 0x01
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_bad_type_returns_none() {
        let mut bytes = make_ndef_uri(0x04, b"example.com");
        bytes[5] = 0x54; // 'T', not 'U'
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_nlen_mismatch_returns_none() {
        let mut bytes = make_ndef_uri(0x04, b"example.com");
        bytes[0] = 0x01; // inflate high byte so size + 2 != len
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_payload_len_mismatch_returns_none() {
        let mut bytes = make_ndef_uri(0x04, b"example.com");
        // Claim payload is 1 byte longer than it is (but keep NLEN correct)
        bytes[4] = bytes[4].wrapping_add(1);
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_invalid_utf8_returns_none() {
        let bytes = make_ndef_uri(0x04, b"\xFF\xFE");
        assert!(parse_ndef_uri(&bytes).is_err());
    }

    #[test]
    fn parse_ndef_uri_round_trip_with_sdm_url_config() {
        let plan = sdm_url_config(
            "https://example.com/?p={picc}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();
        let url = parse_ndef_uri(&plan.ndef_bytes).unwrap();
        assert!(url.as_ref().starts_with("https://example.com/?p="));
        assert!(url.as_ref().contains("&m="));
    }
}
