// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Public SDM verifier types and `Verifier` implementation.

use core::ops::Range;

use arrayvec::ArrayVec;
use thiserror::Error;

use crate::types::file_settings::{EncryptedContent, Offset, PiccData, ReadCtrMirror, Sdm};
use crate::types::{FileSettingsError, KeyNumber, TagTamperStatusReadout};

use super::hex::{decode_hex_array, decode_hex_into, ensure_len};
use super::keys::{SdmKeys, aes_ecb_encrypt_block, derive_sdm_keys_aes, derive_sdm_keys_lrp};
use super::picc::{decrypt_picc_data_aes, decrypt_picc_data_lrp};
use crate::crypto::suite::aes_cbc_decrypt;
use crate::types::file_settings::CryptoMode;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Errors from SDM verification.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdmError {
    /// The computed authentication MAC does not match the value in the NDEF file.
    #[error("MAC verification failed")]
    MacMismatch,
    /// The NDEF file data is too short for the configured SDM offsets.
    #[error("NDEF data too short: need {needed} bytes, have {have}")]
    NdefTooShort { needed: usize, have: usize },
    /// A non-hexadecimal byte was found at a placeholder position.
    #[error("invalid hex character at byte offset {offset}")]
    InvalidHex { offset: usize },
    /// The tag identity data tag byte is malformed; the tag may be counterfeit
    /// or the NDEF file corrupted (NT4H2421Gx §9.3.4).
    #[error("invalid tag identity data tag byte: {0:#04x}")]
    InvalidPiccDataTag(u8),
    /// A required SDM offset or flag is missing from the [`Sdm`] settings.
    ///
    /// [`Sdm`]: crate::types::file_settings::Sdm
    #[error("SDM configuration invalid: {0}")]
    InvalidConfiguration(&'static str),
}

/// Successfully verified SDM data recovered from an NDEF file read.
///
/// All fields are `None` when the corresponding mirror was not enabled
/// in the [`Sdm`] settings.
///
/// [`Sdm`]: crate::types::file_settings::Sdm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmVerification {
    /// Tag UID (7 bytes), if UID mirroring was enabled.
    pub uid: Option<[u8; 7]>,
    /// Read counter value, if counter mirroring was enabled.
    pub read_ctr: Option<u32>,
    /// Tag Tamper status (`TTPermStatus || TTCurrStatus`), if mirrored.
    pub tamper_status: Option<TagTamperStatusReadout>,
    /// Decrypted file data from the encrypted mirror window, if enabled.
    /// Only present when the `alloc` feature is active.
    #[cfg(feature = "alloc")]
    pub enc_file_data: Option<alloc::vec::Vec<u8>>,
}

/// How tag identity data (UID, read counter) is recovered from the NDEF file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum PiccSource {
    /// Encrypted PICCData at the given file byte offset.
    /// AES: 32 hex chars (16 binary bytes). LRP: 48 hex chars (24 binary bytes).
    Encrypted { offset: u32 },
    /// Plaintext ASCII hex mirrors at optional file byte offsets.
    Plain {
        uid_offset: Option<u32>,
        read_ctr_offset: Option<u32>,
    },
    /// No PICC metadata is mirrored.
    None,
}

/// Server-side verifier for NTAG 424 DNA Secure Dynamic Messaging.
///
/// Constructed from [`Sdm`] (obtained from [`AuthenticatedSession::get_file_settings`] or
/// built with [`Sdm::try_new`]) and the active [`CryptoMode`].
///
/// The constructor validates that the settings are internally consistent
/// and sufficient for verification. Only the information needed for
/// verification is stored, making the struct compact and serializable.
///
/// [`Sdm`]: crate::types::file_settings::Sdm
/// [`Sdm::try_new`]: crate::types::file_settings::Sdm::try_new
/// [`AuthenticatedSession::get_file_settings`]: crate::AuthenticatedSession::get_file_settings
///
/// # Example
///
/// ```ignore
/// use ntag424::sdm::{CryptoMode, Verifier};
///
/// let verifier = Verifier::try_new(sdm_settings, CryptoMode::Aes)?;
/// let result = verifier.verify(&ndef_file_bytes, &key)?;
/// println!("UID: {:?}, counter: {:?}", result.uid, result.read_ctr);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Verifier {
    mode: CryptoMode,
    picc_source: PiccSource,
    /// Key number for `SDMMetaRead` (PICCData decryption), if encrypted.
    meta_read_key: Option<KeyNumber>,
    /// Key number for `SDMFileRead` (session keys, MAC, enc file data).
    file_read_key: KeyNumber,
    mac_input_offset: u32,
    mac_offset: u32,
    /// File byte offset of the 2-byte Tag Tamper status, if mirrored.
    tamper_status_offset: Option<u32>,
    /// `SDMENCFileData` placeholder byte range, if configured.
    ///
    /// In ASCII mode this is the full mirrored placeholder length from
    /// `SDMENCOffset .. SDMENCOffset + SDMENCLength`: the returned ciphertext
    /// occupies the whole range as ASCII hex, but only the first half of the
    /// static file placeholder contributes plaintext bytes before encryption.
    enc_data: Option<Range<u32>>,
}

/// Unauthenticated NDEF reads are capped at 256 bytes, so the decrypted
/// `SDMENCFileData` payload can never exceed that size.
const MAX_SDM_ENC_FILE_DATA_BYTES: usize = 256;

impl Verifier {
    /// Create a new verifier, validating that the SDM settings are
    /// consistent and sufficient for verification.
    ///
    /// Only the fields needed for verification are extracted from
    /// `settings`; the full [`Sdm`] is not retained.
    ///
    /// Returns [`SdmError::InvalidConfiguration`] if `SDMFileRead` is
    /// `None` (no MAC key configured). All other invariants are enforced
    /// by [`Sdm::try_new`].
    ///
    /// [`Sdm`]: crate::types::file_settings::Sdm
    /// [`Sdm::try_new`]: crate::types::file_settings::Sdm::try_new
    pub fn try_new(settings: &Sdm, mode: CryptoMode) -> Result<Self, SdmError> {
        let file_read = settings.file_read().ok_or(SdmError::InvalidConfiguration(
            "SDM read access is missing - no MAC key configured",
        ))?;
        let file_read_key = file_read.key();

        let (picc_source, meta_read_key) = match settings.picc_data() {
            PiccData::Encrypted { key, offset, .. } => (
                PiccSource::Encrypted {
                    offset: offset.get(),
                },
                Some(key),
            ),
            PiccData::Plain(plain) => (
                PiccSource::Plain {
                    uid_offset: plain.uid_offset().map(Offset::get),
                    read_ctr_offset: plain.rctr_offset().map(Offset::get),
                },
                None,
            ),
            PiccData::None => (PiccSource::None, None),
        };

        let mac_input_offset = file_read.window().input.get();
        let mac_offset = file_read.window().mac.get();

        let enc_data = file_read.enc().map(|enc| {
            let start = enc.start.get();
            let end = start + enc.length.get();
            start..end
        });

        let tamper_status_offset = settings.tamper_status().map(Offset::get);

        Ok(Self {
            mode,
            picc_source,
            meta_read_key,
            file_read_key,
            mac_input_offset,
            mac_offset,
            tamper_status_offset,
            enc_data,
        })
    }

    pub fn mac_range(&self) -> Range<u32> {
        self.mac_input_offset..self.mac_offset
    }

    /// Validate that the verifier's configuration is internally consistent.
    ///
    /// This should be called after deserializing a verifier to ensure that the
    /// contained offsets and flags are valid and consistent with each other.
    pub fn validate(&self) -> Result<(), FileSettingsError> {
        use crate::types::file_settings::{
            CtrRetAccess, EncFileData, EncLength, FileRead, MacWindow, PiccData, PlainMirror,
            ReadCtrFeatures,
        };

        if !matches!(self.picc_source, PiccSource::Encrypted { .. }) && self.meta_read_key.is_some()
        {
            return Err(FileSettingsError::InvalidSdmFlags);
        }

        let picc_data = match self.picc_source {
            PiccSource::Encrypted { offset } => PiccData::Encrypted {
                offset: Offset::new(offset)?,
                key: self
                    .meta_read_key
                    .ok_or(FileSettingsError::InvalidSdmFlags)?,
                // Following are not relevant for verification
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Free,
                }),
            },
            PiccSource::Plain {
                uid_offset: Some(off),
                read_ctr_offset: None,
            } => PiccData::Plain(PlainMirror::Uid {
                uid: Offset::new(off)?,
            }),
            PiccSource::Plain {
                uid_offset: None,
                read_ctr_offset: Some(off),
            } => PiccData::Plain(PlainMirror::RCtr {
                read_ctr: ReadCtrMirror {
                    offset: Offset::new(off)?,
                    features: ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::Free,
                    },
                },
            }),
            PiccSource::Plain {
                uid_offset: Some(uid_off),
                read_ctr_offset: Some(rctr_off),
            } => PiccData::Plain(PlainMirror::Both {
                uid: Offset::new(uid_off)?,
                read_ctr: ReadCtrMirror {
                    offset: Offset::new(rctr_off)?,
                    features: ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::Free,
                    },
                },
            }),
            PiccSource::Plain {
                uid_offset: None,
                read_ctr_offset: None,
            } => PiccData::None,
            PiccSource::None => PiccData::None,
        };

        let mac_window = MacWindow {
            input: Offset::new(self.mac_input_offset)?,
            mac: Offset::new(self.mac_offset)?,
        };
        let file_read = match &self.enc_data {
            Some(range) => FileRead::MacAndEnc {
                key: self.file_read_key,
                window: mac_window,
                enc: EncFileData {
                    start: Offset::new(range.start)?,
                    length: EncLength::new(
                        range
                            .end
                            .checked_sub(range.start)
                            .ok_or(FileSettingsError::EncLengthInvalid(0))?,
                    )?,
                },
            },
            None => FileRead::MacOnly {
                key: self.file_read_key,
                window: mac_window,
            },
        };

        let tamper_status = self.tamper_status_offset.map(Offset::new).transpose()?;

        Sdm::try_new(picc_data, Some(file_read), tamper_status, self.mode)?;

        Ok(())
    }

    /// Return a new verifier with all range offsets increased by `inc`.
    ///
    /// This is useful for verifying SDM data using content _decoded_ from the NDEF file.
    /// The tag needs indices based on the encoded
    /// NDEF file, but a reader application may want to verify against the decoded content,
    /// e.g. the URL.
    ///
    /// Returns `None` if any offset would underflow or overflow when adjusted by `inc`.
    pub fn with_offset(&self, inc: i32) -> Option<Self> {
        fn add(a: u32, b: i32) -> Option<u32> {
            if b < 0 {
                a.checked_sub(b.checked_neg()? as u32)
            } else {
                a.checked_add(b as u32)
            }
            // max NDEF file size is 256
            .filter(|&r| r <= 255)
        }

        let mut new = self.clone();
        match new.picc_source {
            PiccSource::Encrypted {
                offset: ref mut picc_off,
            } => {
                *picc_off = add(*picc_off, inc)?;
            }
            PiccSource::Plain {
                ref mut uid_offset,
                ref mut read_ctr_offset,
            } => {
                if let Some(uid_off) = uid_offset {
                    *uid_off = add(*uid_off, inc)?;
                }
                if let Some(rctr_off) = read_ctr_offset {
                    *rctr_off = add(*rctr_off, inc)?;
                }
            }
            PiccSource::None => {}
        }
        new.mac_input_offset = add(new.mac_input_offset, inc)?;
        if let Some(tt) = new.tamper_status_offset {
            new.tamper_status_offset = Some(add(tt, inc)?);
        }
        new.mac_offset = add(new.mac_offset, inc)?;
        if let Some(range) = new.enc_data {
            let start = add(range.start, inc)?;
            let end = add(range.end, inc)?;
            new.enc_data = Some(start..end);
        }
        Some(new)
    }

    /// Return the lowest byte offset among all configured SDM data sources.
    pub fn start(&self) -> u32 {
        let picc_offset = match self.picc_source {
            PiccSource::Encrypted { offset } => offset,
            PiccSource::Plain {
                uid_offset,
                read_ctr_offset,
            } => uid_offset
                .unwrap_or(u32::MAX)
                .min(read_ctr_offset.unwrap_or(u32::MAX)),
            PiccSource::None => u32::MAX,
        };
        picc_offset
            .min(self.mac_input_offset)
            .min(self.mac_offset)
            .min(self.tamper_status_offset.unwrap_or(u32::MAX))
            .min(self.enc_data.as_ref().map(|r| r.start).unwrap_or(u32::MAX))
    }

    /// Decrypt or read the tag identity data from an NDEF buffer without verifying the MAC.
    ///
    /// Returns `(uid, read_ctr)`. Each field is `None` when the corresponding
    /// mirror was not enabled in the [`Sdm`] settings.
    ///
    /// `meta_key` is the value of the application key configured as
    /// `SDMMetaRead` (used to decrypt the PICCData blob when
    /// `PiccData::Encrypted` is active). It is ignored for plain or absent
    /// PICC mirrors.
    ///
    /// This is intended for the common two-step server flow where the
    /// `SDMFileRead` key is derived per-tag from the UID (e.g. via
    /// `key_diversification::diversify_ntag424`). Call this first to recover
    /// the UID, derive the file-read key, then pass it to
    /// [`verify_with_meta_key`](Self::verify_with_meta_key).
    ///
    /// [`Sdm`]: crate::types::file_settings::Sdm
    pub fn decrypt_picc_data(
        &self,
        meta_key: &[u8; 16],
        ndef_data: &[u8],
    ) -> Result<(Option<[u8; 7]>, Option<u32>), SdmError> {
        let (uid, ctr_bytes) = self.extract_picc_data(ndef_data, meta_key)?;
        Ok((
            uid,
            ctr_bytes.map(|c| u32::from_le_bytes([c[0], c[1], c[2], 0])),
        ))
    }

    /// The [`CryptoMode`] this verifier was created with.
    pub fn mode(&self) -> CryptoMode {
        self.mode
    }

    /// Application key number for `SDMFileRead` (session key derivation,
    /// MAC verification, and optional `SDMENCFileData` decryption).
    pub fn file_read_key(&self) -> KeyNumber {
        self.file_read_key
    }

    /// Application key number for `SDMMetaRead` (PICCData decryption).
    ///
    /// Returns `None` when PICC metadata is plain-mirrored or absent.
    pub fn meta_read_key(&self) -> Option<KeyNumber> {
        self.meta_read_key
    }

    /// Verify the SDMMAC in the NDEF file data and extract dynamic values.
    ///
    /// `ndef_data` is the raw file content - byte offsets index directly
    /// into this buffer. `key` is the application key used for both
    /// `SDMMetaRead` (PICCData decryption) and `SDMFileRead` (session key
    /// derivation, MAC, and optional `SDMENCFileData` decryption).
    ///
    /// Use [`verify_with_meta_key`](Self::verify_with_meta_key) when
    /// `SDMMetaRead` and `SDMFileRead` are configured to different
    /// application keys.
    pub fn verify(&self, ndef_data: &[u8], key: &[u8; 16]) -> Result<SdmVerification, SdmError> {
        self.verify_inner(ndef_data, key, key)
    }

    /// Like [`verify`](Self::verify), but with a separate key for
    /// `SDMMetaRead` (PICCData decryption).
    ///
    /// Use this when `SDMMetaRead` and `SDMFileRead` point to different
    /// application keys.
    pub fn verify_with_meta_key(
        &self,
        ndef_data: &[u8],
        sdm_file_read_key: &[u8; 16],
        sdm_meta_read_key: &[u8; 16],
    ) -> Result<SdmVerification, SdmError> {
        self.verify_inner(ndef_data, sdm_file_read_key, sdm_meta_read_key)
    }

    fn verify_inner(
        &self,
        ndef_data: &[u8],
        sdm_file_read_key: &[u8; 16],
        sdm_meta_read_key: &[u8; 16],
    ) -> Result<SdmVerification, SdmError> {
        // -- Step 1: Extract UID and SDMReadCtr --
        let (uid, read_ctr_bytes) = self.extract_picc_data(ndef_data, sdm_meta_read_key)?;

        // -- Step 2: Derive SDM session keys --
        let keys = match self.mode {
            CryptoMode::Aes => {
                derive_sdm_keys_aes(sdm_file_read_key, uid.as_ref(), read_ctr_bytes.as_ref())
            }
            CryptoMode::Lrp => {
                derive_sdm_keys_lrp(sdm_file_read_key, uid.as_ref(), read_ctr_bytes.as_ref())
            }
        };

        // -- Step 3: Verify SDMMAC --
        let mac_input_off = self.mac_input_offset as usize;
        let mac_off = self.mac_offset as usize;

        // MAC placeholder: 16 ASCII hex chars (8 binary bytes).
        ensure_len(ndef_data, mac_off + 16)?;

        let mac_input = &ndef_data[mac_input_off..mac_off];
        let expected_mac = decode_hex_array::<8>(ndef_data, mac_off)?;

        if !keys.verify_mac(mac_input, &expected_mac) {
            return Err(SdmError::MacMismatch);
        }

        // -- Step 4: Decrypt SDMENCFileData if configured --
        let enc_file_data =
            self.decrypt_enc_file_data(ndef_data, &keys, read_ctr_bytes.as_ref())?;
        let tamper_status = self.extract_tamper_status(
            ndef_data,
            enc_file_data.as_ref().map(|data| data.as_slice()),
        )?;

        Ok(SdmVerification {
            uid,
            read_ctr: read_ctr_bytes.map(|c| u32::from_le_bytes([c[0], c[1], c[2], 0])),
            tamper_status,
            #[cfg(feature = "alloc")]
            enc_file_data: enc_file_data.map(|data| data.into_iter().collect()),
        })
    }

    /// Extract UID and SDMReadCtr based on the PICC source configuration.
    #[allow(clippy::type_complexity)]
    fn extract_picc_data(
        &self,
        ndef_data: &[u8],
        meta_key: &[u8; 16],
    ) -> Result<(Option<[u8; 7]>, Option<[u8; 3]>), SdmError> {
        match &self.picc_source {
            PiccSource::Encrypted { offset } => {
                let offset = *offset as usize;
                ensure_len(ndef_data, offset + self.mode.picc_blob_ascii_len() as usize)?;
                match self.mode {
                    CryptoMode::Aes => {
                        let enc = decode_hex_array::<16>(ndef_data, offset)?;
                        let picc = decrypt_picc_data_aes(meta_key, &enc)?;
                        Ok((picc.uid, picc.read_ctr))
                    }
                    CryptoMode::Lrp => {
                        let wire = decode_hex_array::<24>(ndef_data, offset)?;
                        let picc = decrypt_picc_data_lrp(meta_key, &wire)?;
                        Ok((picc.uid, picc.read_ctr))
                    }
                }
            }
            PiccSource::Plain {
                uid_offset,
                read_ctr_offset,
            } => {
                let uid = if let Some(offset) = uid_offset {
                    let offset = *offset as usize;
                    // 7 binary bytes = 14 ASCII hex chars.
                    ensure_len(ndef_data, offset + 14)?;
                    Some(decode_hex_array::<7>(ndef_data, offset)?)
                } else {
                    None
                };
                let read_ctr = if let Some(offset) = read_ctr_offset {
                    let offset = *offset as usize;
                    // 3 binary bytes = 6 ASCII hex chars.
                    ensure_len(ndef_data, offset + 6)?;
                    let mut ctr = decode_hex_array::<3>(ndef_data, offset)?;
                    // Plain ASCII mirror is MSB-first; crypto uses LSB-first.
                    ctr.reverse();
                    Some(ctr)
                } else {
                    None
                };
                Ok((uid, read_ctr))
            }
            PiccSource::None => Ok((None, None)),
        }
    }

    /// Decrypt SDMENCFileData (§9.3.6).
    fn decrypt_enc_file_data(
        &self,
        ndef_data: &[u8],
        keys: &SdmKeys,
        read_ctr: Option<&[u8; 3]>,
    ) -> Result<Option<ArrayVec<u8, MAX_SDM_ENC_FILE_DATA_BYTES>>, SdmError> {
        let range = match &self.enc_data {
            Some(r) => r,
            None => return Ok(None),
        };
        let start = range.start as usize;
        let ascii_len = (range.end - range.start) as usize;
        ensure_len(ndef_data, start + ascii_len)?;

        let binary_len = ascii_len / 2;
        let mut ct = ArrayVec::<u8, MAX_SDM_ENC_FILE_DATA_BYTES>::new();
        for _ in 0..binary_len {
            ct.try_push(0).map_err(|_| {
                SdmError::InvalidConfiguration(
                    "enc_data decrypted length exceeds verifier buffer limit",
                )
            })?;
        }
        decode_hex_into(ct.as_mut_slice(), ndef_data, start)?;

        let ctr = read_ctr.copied().unwrap_or([0; 3]);

        match keys {
            SdmKeys::Aes { enc_key, .. } => {
                // IV = AES-ECB-ENC(SesSDMFileReadENCKey, SDMReadCtr || 0^13)
                let mut iv_input = [0u8; 16];
                iv_input[..3].copy_from_slice(&ctr);
                let iv = aes_ecb_encrypt_block(enc_key, &iv_input);
                aes_cbc_decrypt(enc_key, &iv, ct.as_mut_slice()).ok_or(
                    SdmError::InvalidConfiguration(
                        "AES decryption failed: cipher buffer is not block-aligned",
                    ),
                )?;
            }
            SdmKeys::Lrp { enc, .. } => {
                // Counter = SDMReadCtr || 000000 (6 bytes, §9.3.6.2).
                let mut counter = [0u8; 6];
                counter[..3].copy_from_slice(&ctr);
                enc.lricb_decrypt_in_place(&mut counter, ct.as_mut_slice())
                    .ok_or(SdmError::InvalidConfiguration(
                        "LRICB decryption failed: invalid buffer length",
                    ))?;
            }
        }

        Ok(Some(ct))
    }

    fn extract_tamper_status(
        &self,
        ndef_data: &[u8],
        enc_file_data: Option<&[u8]>,
    ) -> Result<Option<TagTamperStatusReadout>, SdmError> {
        let Some(offset) = self.tamper_status_offset.map(|offset| offset as usize) else {
            return Ok(None);
        };

        if let Some(range) = &self.enc_data {
            let start = range.start as usize;
            let end = range.end as usize;
            if offset >= start && offset < end {
                let relative_plain = offset - start;
                let plain = enc_file_data.ok_or(SdmError::InvalidConfiguration(
                    "tamper_status inside enc_data requires decrypted file data",
                ))?;
                if relative_plain + 2 > plain.len() {
                    return Err(SdmError::InvalidConfiguration(
                        "tamper_status offset exceeds enc_data bounds",
                    ));
                }
                return Ok(Some(TagTamperStatusReadout::new(
                    plain[relative_plain],
                    plain[relative_plain + 1],
                )));
            }
        }

        ensure_len(ndef_data, offset + 2)?;
        Ok(Some(TagTamperStatusReadout::new(
            ndef_data[offset],
            ndef_data[offset + 1],
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::file_settings::{
        CtrRetAccess, EncFileData, EncLength, EncryptedContent, FileRead, MacWindow, PlainMirror,
        ReadCtrFeatures,
    };

    #[test]
    fn validate_accepts_encrypted_picc_with_enc_data() {
        let settings = Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key1,
                offset: Offset::new(0).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                }),
            },
            Some(FileRead::MacAndEnc {
                key: KeyNumber::Key2,
                window: MacWindow {
                    input: Offset::new(32).unwrap(),
                    mac: Offset::new(64).unwrap(),
                },
                enc: EncFileData {
                    start: Offset::new(32).unwrap(),
                    length: EncLength::new(32).unwrap(),
                },
            }),
            None,
            CryptoMode::Aes,
        )
        .unwrap();

        let verifier = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();

        assert_eq!(verifier.validate(), Ok(()));
    }

    #[test]
    fn validate_accepts_plain_uid_and_read_ctr() {
        let settings = Sdm::try_new(
            PiccData::Plain(PlainMirror::Both {
                uid: Offset::new(0).unwrap(),
                read_ctr: ReadCtrMirror {
                    offset: Offset::new(14).unwrap(),
                    features: ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::NoAccess,
                    },
                },
            }),
            Some(FileRead::MacOnly {
                key: KeyNumber::Key2,
                window: MacWindow {
                    input: Offset::new(0).unwrap(),
                    mac: Offset::new(20).unwrap(),
                },
            }),
            None,
            CryptoMode::Aes,
        )
        .unwrap();

        let verifier = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();

        assert_eq!(verifier.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_encrypted_picc_without_meta_key() {
        let verifier = Verifier {
            mode: CryptoMode::Aes,
            picc_source: PiccSource::Encrypted { offset: 0 },
            meta_read_key: None,
            file_read_key: KeyNumber::Key0,
            mac_input_offset: 32,
            mac_offset: 32,
            tamper_status_offset: None,
            enc_data: None,
        };

        assert_eq!(verifier.validate(), Err(FileSettingsError::InvalidSdmFlags));
    }

    #[test]
    fn validate_rejects_meta_key_without_encrypted_picc() {
        let verifier = Verifier {
            mode: CryptoMode::Aes,
            picc_source: PiccSource::None,
            meta_read_key: Some(KeyNumber::Key0),
            file_read_key: KeyNumber::Key0,
            mac_input_offset: 0,
            mac_offset: 0,
            tamper_status_offset: None,
            enc_data: None,
        };

        assert_eq!(verifier.validate(), Err(FileSettingsError::InvalidSdmFlags));
    }

    #[test]
    fn validate_rejects_inverted_enc_data_range_without_panicking() {
        let verifier = Verifier {
            mode: CryptoMode::Aes,
            picc_source: PiccSource::Encrypted { offset: 0 },
            meta_read_key: Some(KeyNumber::Key0),
            file_read_key: KeyNumber::Key0,
            mac_input_offset: 32,
            mac_offset: 96,
            tamper_status_offset: None,
            #[allow(clippy::reversed_empty_ranges)]
            enc_data: Some(80..48),
        };

        assert_eq!(
            verifier.validate(),
            Err(FileSettingsError::EncLengthInvalid(0))
        );
    }

    #[test]
    fn validate_rejects_mac_input_after_mac() {
        let verifier = Verifier {
            mode: CryptoMode::Aes,
            picc_source: PiccSource::None,
            meta_read_key: None,
            file_read_key: KeyNumber::Key0,
            mac_input_offset: 1,
            mac_offset: 0,
            tamper_status_offset: None,
            enc_data: None,
        };

        assert_eq!(
            verifier.validate(),
            Err(FileSettingsError::MacInputAfterMac)
        );
    }

    fn base_verifier() -> Verifier {
        Verifier {
            mode: CryptoMode::Aes,
            picc_source: PiccSource::None,
            meta_read_key: None,
            file_read_key: KeyNumber::Key0,
            mac_input_offset: 50,
            mac_offset: 80,
            tamper_status_offset: None,
            enc_data: None,
        }
    }

    #[test]
    fn start_encrypted_picc_is_earliest() {
        let v = Verifier {
            picc_source: PiccSource::Encrypted { offset: 10 },
            meta_read_key: Some(KeyNumber::Key1),
            mac_input_offset: 50,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 10);
    }

    #[test]
    fn start_mac_input_is_earliest() {
        let v = Verifier {
            picc_source: PiccSource::Encrypted { offset: 20 },
            meta_read_key: Some(KeyNumber::Key1),
            mac_input_offset: 15,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 15);
    }

    #[test]
    fn start_mac_offset_is_earliest() {
        let v = Verifier {
            mac_input_offset: 50,
            mac_offset: 5,
            ..base_verifier()
        };
        assert_eq!(v.start(), 5);
    }

    #[test]
    fn start_tamper_status_is_earliest() {
        let v = Verifier {
            mac_input_offset: 50,
            mac_offset: 80,
            tamper_status_offset: Some(3),
            ..base_verifier()
        };
        assert_eq!(v.start(), 3);
    }

    #[test]
    fn start_enc_data_is_earliest() {
        let v = Verifier {
            mac_input_offset: 50,
            mac_offset: 80,
            enc_data: Some(8..40),
            ..base_verifier()
        };
        assert_eq!(v.start(), 8);
    }

    #[test]
    fn start_plain_uid_offset_is_earliest() {
        let v = Verifier {
            picc_source: PiccSource::Plain {
                uid_offset: Some(5),
                read_ctr_offset: Some(20),
            },
            mac_input_offset: 50,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 5);
    }

    #[test]
    fn start_plain_read_ctr_offset_is_earliest() {
        let v = Verifier {
            picc_source: PiccSource::Plain {
                uid_offset: Some(30),
                read_ctr_offset: Some(7),
            },
            mac_input_offset: 50,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 7);
    }

    #[test]
    fn start_plain_only_uid_offset_present() {
        let v = Verifier {
            picc_source: PiccSource::Plain {
                uid_offset: Some(12),
                read_ctr_offset: None,
            },
            mac_input_offset: 50,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 12);
    }

    #[test]
    fn start_picc_none_falls_back_to_mac_input() {
        let v = base_verifier();
        // PiccSource::None, no tamper, no enc_data → min(mac_input=50, mac=80)
        assert_eq!(v.start(), 50);
    }

    #[test]
    fn start_plain_both_none_falls_back_to_mac_input() {
        let v = Verifier {
            picc_source: PiccSource::Plain {
                uid_offset: None,
                read_ctr_offset: None,
            },
            mac_input_offset: 50,
            mac_offset: 80,
            ..base_verifier()
        };
        assert_eq!(v.start(), 50);
    }
}
