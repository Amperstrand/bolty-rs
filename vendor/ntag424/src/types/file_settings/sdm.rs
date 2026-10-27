// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! SDM (Secure Dynamic Messaging) configuration types for the NDEF file.
//!
//! The top-level type is [`Sdm`], constructed via [`Sdm::try_new`].  All byte
//! offsets stored here are indices into the **raw NDEF file** on the tag (the
//! 256-byte file, not the URL string); [`crate::sdm_url_config!`] handles the
//! URL-to-NDEF offset arithmetic automatically.
//!
//! # Type ownership of byte ranges
//!
//! | Type | Byte range owned |
//! |------|-----------------|
//! | [`PiccData::Plain`] | UID placeholder (14 bytes) and/or read-counter placeholder (6 bytes) |
//! | [`PiccData::Encrypted`] | PICCData blob: 32 bytes (AES) or 48 bytes (LRP) |
//! | [`MacWindow::mac`] | 16-byte authentication MAC placeholder |
//! | [`EncFileData`] | `length` bytes (multiple of 32); first half is plaintext input, second half is ciphertext output |
//! | `tamper_status` | 2-byte tag tamper status placeholder |
//!
//! `try_new` enforces that all placeholder ranges are non-overlapping, with
//! one exception: the tamper-status placeholder (2 bytes) may lie inside
//! `EncFileData`, but only within its **first (plaintext) half** — see below.
//!
//! # `MacWindow` and `EncFileData` relationship
//!
//! `MacWindow` defines *what is authenticated*: bytes `[input, mac)` are fed
//! into the CMAC, and the 16-byte result is written at `mac`.  `EncFileData`
//! is a sub-range that must lie entirely within `[input, mac)`: the tag
//! encrypts those bytes in place, so the MAC covers the ciphertext, not the
//! original plaintext.
//!
//! The `EncFileData` range is split into two equal halves: the first half
//! holds the plaintext data that will be encrypted (readable/writable before
//! the tap), and the tag overwrites the second half with the ciphertext on
//! each read.  The tamper-status placeholder may overlap with `EncFileData`
//! only if it fits entirely inside the first (plaintext) half; placing it in
//! the ciphertext half is rejected by `try_new`.

use crate::types::KeyNumber;

use super::access::CtrRetAccess;
use super::error::{FileSettingsError, OverlapKind};

/// Cryptographic suite used for SDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CryptoMode {
    /// AES-128 based SDM (§9.3 AES path).
    Aes,
    /// Leakage Resilient Primitive (§9.3 LRP path).
    Lrp,
}

impl CryptoMode {
    /// Number of ASCII hex characters occupied by the encrypted PICCData blob.
    pub const fn picc_blob_ascii_len(self) -> u32 {
        match self {
            Self::Aes => PICC_BLOB_LEN_AES,
            Self::Lrp => PICC_BLOB_LEN_LRP,
        }
    }
}

/// A 24-bit byte offset into a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset(pub(super) u32);

impl Offset {
    /// Create an offset. Returns `Err` if `v > 0x00FF_FFFF`.
    pub const fn new(v: u32) -> Result<Self, FileSettingsError> {
        if v > 0x00FF_FFFF {
            Err(FileSettingsError::OffsetOutOfRange(v))
        } else {
            Ok(Self(v))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Placeholder length for the encrypted file data region.
///
/// Must be a positive multiple of 32. The tag encrypts the first half of this
/// range; the second half is the ciphertext written into the file.
///
/// NT4H2421Gx Table 69, `SDMENCLength`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncLength(pub(super) u32);

impl EncLength {
    /// Create an [`EncLength`]. Returns `Err` if `v == 0`, `v % 32 != 0`, or `v > 0x00FF_FFFF`.
    pub const fn new(v: u32) -> Result<Self, FileSettingsError> {
        if v == 0 || !v.is_multiple_of(32) || v > 0x00FF_FFFF {
            Err(FileSettingsError::EncLengthInvalid(v))
        } else {
            Ok(Self(v))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Features associated with read counter mirroring.
///
/// Embedded in variants of [`PlainMirror`] and [`EncryptedContent`] that
/// include the read counter; not present when only the UID is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrFeatures {
    /// Read counter limit.
    ///
    /// `None` means unlimited. When `Some(n)`, unauthenticated SDM reads are
    /// permitted only while the counter is below `n`.
    pub limit: Option<u32>,
    /// Who may retrieve the read counter via
    /// [`AuthenticatedSession::get_file_counters`](`crate::AuthenticatedSession::get_file_counters`).
    pub ret_access: CtrRetAccess,
}

/// File offset and features for read counter mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrMirror {
    /// Start of the 6-byte ASCII read counter placeholder.
    pub offset: Offset,
    /// Read counter features (limit and retrieval access right).
    pub features: ReadCtrFeatures,
}

/// Plain ASCII hex mirroring of tag identity data into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainMirror {
    /// Only the 7-byte UID (14 ASCII chars) is mirrored.
    Uid { uid: Offset },
    /// Only the 3-byte `SDMReadCtr` (6 ASCII chars) is mirrored.
    RCtr { read_ctr: ReadCtrMirror },
    /// Both UID and `SDMReadCtr` are mirrored.
    Both {
        uid: Offset,
        read_ctr: ReadCtrMirror,
    },
}

impl PlainMirror {
    pub const fn uid_offset(&self) -> Option<Offset> {
        match self {
            Self::Uid { uid } | Self::Both { uid, .. } => Some(*uid),
            Self::RCtr { .. } => None,
        }
    }

    pub const fn rctr_offset(&self) -> Option<Offset> {
        match self {
            Self::RCtr { read_ctr } | Self::Both { read_ctr, .. } => Some(read_ctr.offset),
            Self::Uid { .. } => None,
        }
    }
}

/// Content of the encrypted tag identity data blob (PICCData).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedContent {
    /// Only the UID is inside the encrypted blob.
    Uid,
    /// Only `SDMReadCtr` is inside the encrypted blob.
    RCtr(ReadCtrFeatures),
    /// Both UID and `SDMReadCtr` are inside the encrypted blob.
    Both(ReadCtrFeatures),
}

impl EncryptedContent {
    pub const fn includes_uid(&self) -> bool {
        matches!(self, Self::Uid | Self::Both(_))
    }

    pub const fn includes_rctr(&self) -> bool {
        matches!(self, Self::RCtr(_) | Self::Both(_))
    }

    pub const fn features(&self) -> Option<&ReadCtrFeatures> {
        match self {
            Self::Uid => None,
            Self::RCtr(f) | Self::Both(f) => Some(f),
        }
    }
}

/// How the tag identity data (UID and/or read counter) is mirrored into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiccData {
    /// No tag identity data mirrored.
    None,
    /// UID and/or read counter mirrored as plain ASCII hex.
    Plain(PlainMirror),
    /// UID and/or read counter mirrored inside an encrypted tag identity data blob.
    Encrypted {
        /// AppKey used for decryption of the identity data blob (`SDMMetaRead`).
        key: KeyNumber,
        /// Start of the encrypted identity data placeholder.
        offset: Offset,
        /// Which identity data is inside the encrypted blob, and read counter features if applicable.
        content: EncryptedContent,
    },
}

impl PiccData {
    pub const fn includes_uid(&self) -> bool {
        matches!(
            self,
            Self::Plain(PlainMirror::Uid { .. } | PlainMirror::Both { .. })
                | Self::Encrypted {
                    content: EncryptedContent::Uid | EncryptedContent::Both(_),
                    ..
                }
        )
    }

    pub const fn includes_rctr(&self) -> bool {
        matches!(
            self,
            Self::Plain(PlainMirror::RCtr { .. } | PlainMirror::Both { .. })
                | Self::Encrypted {
                    content: EncryptedContent::RCtr(_) | EncryptedContent::Both(_),
                    ..
                }
        )
    }

    /// Read counter limit, if any counter-bearing mirror is configured.
    pub const fn read_ctr_limit(&self) -> Option<u32> {
        match self {
            Self::Plain(PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. }) => {
                read_ctr.features.limit
            }
            Self::Encrypted {
                content: EncryptedContent::RCtr(f) | EncryptedContent::Both(f),
                ..
            } => f.limit,
            _ => None,
        }
    }

    /// `SDMCtrRet` access right, defaulting to `NoAccess` when no read counter is mirrored.
    pub(super) const fn ctr_ret(&self) -> CtrRetAccess {
        match self {
            Self::Plain(PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. }) => {
                read_ctr.features.ret_access
            }
            Self::Encrypted {
                content: EncryptedContent::RCtr(f) | EncryptedContent::Both(f),
                ..
            } => f.ret_access,
            _ => CtrRetAccess::NoAccess,
        }
    }
}

/// MAC input window for the SDM authentication code.
///
/// `input.get() ≤ mac.get()` is checked by [`Sdm::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacWindow {
    /// Index of first byte of file data covered by the authentication MAC.
    ///
    /// By default this is the start of the file (offset 0).
    pub input: Offset,
    /// Start of the 16-byte ASCII authentication MAC placeholder.
    ///
    /// The MAC covers the file data in the range `[input, mac)`.
    pub mac: Offset,
}

/// Encrypted file data placeholder range.
///
/// This range must lie within the MAC window (checked by [`Sdm::try_new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncFileData {
    /// Start of the ASCII placeholder in the file.
    pub start: Offset,
    /// Length of the ASCII placeholder - must be a positive multiple of 32.
    pub length: EncLength,
}

/// SDM file-read configuration: MAC key, window, and optional encrypted file data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRead {
    /// Authentication MAC only — no encrypted file data.
    MacOnly { key: KeyNumber, window: MacWindow },
    /// Authentication MAC plus encrypted file data.
    ///
    /// Requires [`PiccData::Encrypted`] with [`EncryptedContent::Both`],
    /// or [`PiccData::Plain`] with [`PlainMirror::Both`].
    MacAndEnc {
        key: KeyNumber,
        window: MacWindow,
        enc: EncFileData,
    },
}

impl FileRead {
    pub const fn key(&self) -> KeyNumber {
        match self {
            Self::MacOnly { key, .. } | Self::MacAndEnc { key, .. } => *key,
        }
    }

    pub const fn window(&self) -> &MacWindow {
        match self {
            Self::MacOnly { window, .. } | Self::MacAndEnc { window, .. } => window,
        }
    }

    pub const fn enc(&self) -> Option<&EncFileData> {
        match self {
            Self::MacOnly { .. } => None,
            Self::MacAndEnc { enc, .. } => Some(enc),
        }
    }
}

/// ASCII placeholder widths (bytes in the NDEF file, since ASCII = 1 byte/char).
const UID_PLACEHOLDER_LEN: u32 = 14; // 7 binary bytes × 2 hex chars
const RCTR_PLACEHOLDER_LEN: u32 = 6; // 3 binary bytes × 2 hex chars
const TT_PLACEHOLDER_LEN: u32 = 2; // 1 binary byte × 2 hex chars
const MAC_PLACEHOLDER_LEN: u32 = 16; // 8 binary bytes × 2 hex chars (truncated CMAC)
const PICC_BLOB_LEN_AES: u32 = 32; // 16 binary bytes × 2 hex chars
const PICC_BLOB_LEN_LRP: u32 = 48; // 24 binary bytes × 2 hex chars (8 PICCRand + 16 ct)

/// Returns `true` when byte ranges `[a, a+a_len)` and `[b, b+b_len)` overlap.
const fn ranges_overlap(a: u32, a_len: u32, b: u32, b_len: u32) -> bool {
    !(a + a_len <= b || b + b_len <= a)
}

/// Secure Dynamic Messaging (SDM) configuration for a file.
///
/// SDM lets the tag deliver authenticated, replay-protected dynamic content
/// to readers that have **not** authenticated — typically an NDEF URL containing
/// a fresh UID, a monotonically increasing read counter, optional encrypted file
/// data, and a truncated authentication MAC.
///
/// Construct via [`Sdm::try_new`]. Use
/// [`Verifier`](`crate::sdm::Verifier`)
/// to verify and parse the SDM content on the server side, or
/// [`sdm_url_config!`](`crate::sdm_url_config!`) as a convenience to build
/// the NDEF URL and configuration together from a template.
///
/// Mirror placeholders in the NDEF file are ASCII hex strings; their byte widths are:
/// UID = 14, read counter = 6, tag tamper status = 2, authentication MAC = 16,
/// encrypted identity data blob = 32 (AES) or 48 (LRP).
///
/// ## Configuration
///
/// This struct stores SDM configuration information about:
///
/// **Tag identity mirroring ([`PiccData`])** — what the tag writes into the NDEF file on every read, and how:
/// - [`Plain`] — UID (14 ASCII chars) and/or read counter (6 ASCII chars) are written as plain hex
///   at fixed offsets. Simple to parse, but not authenticated on their own.
/// - [`Encrypted`] — UID and/or read counter are packed into an encrypted identity blob (PICCData)
///   at one offset, decryptable with one of the stored keys. Provides confidentiality for the identity
///   data itself.
/// - [`None`] — no identity data mirrored.
///
/// **Authentication MAC ([`FileRead`])** — a truncated CMAC over a configurable byte window of the file,
/// placed as 16 ASCII chars at a fixed offset. Verifies integrity and authenticity. When the read
/// counter is included in the MAC input and the server tracks its monotonic increase, this also
/// prevents replay. Options on what the MAC covers and how it is computed:
/// - [`MacOnly`] — MAC only; the [`MacWindow`] specifies where the MAC input starts and where the
///   16-char placeholder sits.
/// - [`MacAndEnc`] — MAC plus encrypted file data: a region of the NDEF file is replaced with its
///   LRP/AES ciphertext. The [`EncFileData`] offset and length (multiple of 32) must lie within the MAC
///   window, and `PiccData` must include both UID and read counter.
///
/// **Tag tamper status** — an optional 2-char ASCII placeholder at a configurable offset,
/// populated with the tag's tamper loop state (requires tamper-detect version of hardware).
///
/// **Read counter limit** — when a read counter is mirrored, an optional `limit` can be set:
/// unauthenticated SDM reads are refused once the counter reaches the limit.
///
/// **Counter retrieval access** ([`CtrRetAccess`]) — who may read back the raw counter value via
/// [`AuthenticatedSession::get_file_counters`].
///
/// The [`crate::sdm_url_config!`] macro builds a `(NDEF bytes, Sdm)` pair from a URL template and handles
/// offset arithmetic automatically — prefer it over constructing this struct directly if your NDEF
/// is a URL.
///
/// NT4H2421Gx §9.3, §10.7.1 Table 69.
///
/// [`PiccData`]: PiccData
/// [`Plain`]: PiccData::Plain
/// [`Encrypted`]: PiccData::Encrypted
/// [`None`]: PiccData::None
/// [`FileRead`]: FileRead
/// [`MacOnly`]: FileRead::MacOnly
/// [`MacAndEnc`]: FileRead::MacAndEnc
/// [`MacWindow`]: MacWindow
/// [`EncFileData`]: EncFileData
/// [`CtrRetAccess`]: CtrRetAccess
/// [`AuthenticatedSession::get_file_counters`]: crate::AuthenticatedSession::get_file_counters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sdm {
    picc_data: PiccData,
    file_read: Option<FileRead>,
    tamper_status: Option<Offset>,
}

impl Sdm {
    /// SDM fully disabled: no PICC data mirroring, no file-read MAC, no tamper status.
    ///
    /// Use with [`crate::FileSettingsUpdate::with_sdm`] to clear SDM when wiping a card:
    ///
    /// ```ignore
    /// let update = settings.into_update().with_sdm(Sdm::disabled());
    /// session.change_file_settings(transport, file, &update).await?;
    /// ```
    pub const fn disabled() -> Self {
        Self {
            picc_data: PiccData::None,
            file_read: None,
            tamper_status: None,
        }
    }

    /// Returns the tag identity data (PICCData) mirror configuration.
    pub const fn picc_data(self) -> PiccData {
        self.picc_data
    }

    /// Returns the file-read key and MAC window, or `None` if no MAC is configured.
    pub const fn file_read(self) -> Option<FileRead> {
        self.file_read
    }

    /// Returns the tag tamper status mirror offset, or `None` if not mirrored.
    pub const fn tamper_status(self) -> Option<Offset> {
        self.tamper_status
    }

    /// Construct and validate SDM settings.
    ///
    /// Checks:
    /// - `window.input ≤ window.mac`
    /// - (`MacAndEnc`): encrypted file data range lies within the MAC window
    /// - (`MacAndEnc`): `picc_data` includes both UID and read counter
    /// - pairwise non-overlap between all placeholders, including the encrypted
    ///   identity data blob (NT4H2421Gx Table 71); blob size is 32 bytes for AES,
    ///   48 bytes for LRP
    /// - (`MacAndEnc`): `tamper_status`, if inside the encrypted file data range,
    ///   must fall entirely within the plaintext half
    pub const fn try_new(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
        mode: CryptoMode,
    ) -> Result<Self, FileSettingsError> {
        // Run all mode-independent checks first.
        if let Err(e) = Self::try_new_inner(picc_data, file_read, tamper_status) {
            return Err(e);
        }

        // Check overlap between the encrypted PICCData blob and every other placeholder.
        // The blob size depends on mode, so this check requires a CryptoMode parameter.
        if let PiccData::Encrypted { offset, .. } = picc_data {
            let picc_len = mode.picc_blob_ascii_len();
            let picc_start = offset.0;

            let tt_range: Option<(u32, u32)> = if let Some(tt) = tamper_status {
                Some((tt.0, TT_PLACEHOLDER_LEN))
            } else {
                None
            };
            let mac_range: Option<(u32, u32)> = if let Some(ref fr) = file_read {
                Some((fr.window().mac.0, MAC_PLACEHOLDER_LEN))
            } else {
                None
            };
            let enc_range: Option<(u32, u32)> =
                if let Some(FileRead::MacAndEnc { enc, .. }) = file_read {
                    Some((enc.start.0, enc.length.0))
                } else {
                    None
                };

            macro_rules! check_picc {
                ($other:expr, $kind:expr) => {
                    if let Some((b, bl)) = $other {
                        if ranges_overlap(picc_start, picc_len, b, bl) {
                            return Err(FileSettingsError::MirrorsOverlap($kind));
                        }
                    }
                };
            }

            // When PiccData is Encrypted, uid_range and rctr_range are both None
            // (plain mirrors and encrypted mirrors are mutually exclusive), so we
            // only need to check tamper status, MAC, and enc file data.
            check_picc!(tt_range, OverlapKind::PiccAndTamper);
            check_picc!(mac_range, OverlapKind::PiccAndMac);
            check_picc!(enc_range, OverlapKind::PiccAndEnc);
        }

        Ok(Self {
            picc_data,
            file_read,
            tamper_status,
        })
    }

    /// Deserialize SDM settings decoded from wire bytes.
    ///
    /// Performs the same checks as [`try_new`](Self::try_new) except the
    /// overlap check against the encrypted PICCData blob, which requires a
    /// [`CryptoMode`] that is not encoded in the wire format.
    pub(super) const fn try_new_from_wire(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
    ) -> Result<Self, FileSettingsError> {
        Self::try_new_inner(picc_data, file_read, tamper_status)
    }

    const fn try_new_inner(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
    ) -> Result<Self, FileSettingsError> {
        // mac_input <= mac
        if let Some(ref fr) = file_read {
            let w = fr.window();
            if w.input.0 > w.mac.0 {
                return Err(FileSettingsError::MacInputAfterMac);
            }
        }

        // enc file data must be within the MAC window
        if let Some(FileRead::MacAndEnc { window: w, enc, .. }) = file_read {
            let enc_end = enc.start.0 + enc.length.0;
            // enc range: [enc.start, enc_end)
            // MAC window: [w.input, w.mac + MAC_PLACEHOLDER_LEN)
            if enc.start.0 < w.input.0 || enc_end > w.mac.0 {
                return Err(FileSettingsError::EncOutsideMacWindow);
            }

            // MacAndEnc requires both UID and RCtr in picc_data
            if !picc_data.includes_uid() || !picc_data.includes_rctr() {
                return Err(FileSettingsError::EncRequiresBothMirrors);
            }
        }

        // Collect placeholder positions for pairwise overlap checks.
        let uid_range: Option<(u32, u32)> = match picc_data {
            PiccData::Plain(PlainMirror::Uid { uid } | PlainMirror::Both { uid, .. }) => {
                Some((uid.0, UID_PLACEHOLDER_LEN))
            }
            _ => None,
        };
        let rctr_range: Option<(u32, u32)> = match picc_data {
            PiccData::Plain(
                PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. },
            ) => Some((read_ctr.offset.0, RCTR_PLACEHOLDER_LEN)),
            _ => None,
        };
        let tt_range: Option<(u32, u32)> = if let Some(tt) = tamper_status {
            Some((tt.0, TT_PLACEHOLDER_LEN))
        } else {
            None
        };
        let mac_range: Option<(u32, u32)> = if let Some(ref fr) = file_read {
            Some((fr.window().mac.0, MAC_PLACEHOLDER_LEN))
        } else {
            None
        };
        let enc_range: Option<(u32, u32)> = if let Some(FileRead::MacAndEnc { enc, .. }) = file_read
        {
            Some((enc.start.0, enc.length.0))
        } else {
            None
        };

        macro_rules! check {
            ($a:expr, $b:expr, $kind:expr) => {
                if let (Some((a, al)), Some((b, bl))) = ($a, $b) {
                    if ranges_overlap(a, al, b, bl) {
                        return Err(FileSettingsError::MirrorsOverlap($kind));
                    }
                }
            };
        }

        check!(uid_range, rctr_range, OverlapKind::UidAndRCtr);
        check!(uid_range, tt_range, OverlapKind::UidAndTamper);
        check!(rctr_range, tt_range, OverlapKind::RCtrAndTamper);
        check!(uid_range, mac_range, OverlapKind::UidAndMac);
        check!(rctr_range, mac_range, OverlapKind::RCtrAndMac);
        check!(tt_range, mac_range, OverlapKind::TamperAndMac);
        check!(enc_range, uid_range, OverlapKind::EncAndUid);
        check!(enc_range, rctr_range, OverlapKind::EncAndRCtr);

        // If tamper status is inside the encrypted file data range, it must be in the plain half.
        if let (Some((tt, tt_len)), Some((enc_start, enc_len))) = (tt_range, enc_range)
            && ranges_overlap(tt, tt_len, enc_start, enc_len)
        {
            let plain_half_end = enc_start + enc_len / 2;
            if tt + tt_len > plain_half_end {
                return Err(FileSettingsError::MirrorsOverlap(
                    OverlapKind::TamperInCiphertextHalf,
                ));
            }
        }

        Ok(Self {
            picc_data,
            file_read,
            tamper_status,
        })
    }
}
