// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! File settings for [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`)
//! and [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
//!
//! [`FileSettingsView`] is the decoded result returned by
//! [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`).
//! [`FileSettingsUpdate`] is the update input for
//! [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
//! [`Sdm`] holds Secure Dynamic Messaging configuration; construct it via [`Sdm::try_new`].
//!
//! `ChangeFileSettings` overwrites all mutable file-settings fields together.
//! When modifying an existing file, the safest pattern is:
//!
//! 1. Read the current settings with [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`)
//! 2. Convert the returned [`FileSettingsView`] with [`FileSettingsView::into_update`]
//! 3. Apply only the changes you intend before calling
//!    [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`)
//!
//! Starting from [`FileSettingsUpdate::new`] is best reserved for cases where
//! you intentionally want to replace the full communication-mode and
//! access-rights configuration.
//!
//! Wire format references: NT4H2421Gx §10.7.1, §10.7.2; access-rights nibble layout
//! per §8.2.3.3, Tables 6 and 7; CommMode encoding per Table 22.
//!
//! # Module layout
//!
//! | Sub-module | Contents |
//! |---|---|
//! | [`access`] | `FileType`, `CommMode`, `Access`, `CtrRetAccess`, `AccessRights` |
//! | [`sdm`] | `Sdm` and all SDM mirror types (`Offset`, `PlainMirror`, `PiccData`, …) |
//! | [`codec`] | `FileSettingsView` (decoder) and `FileSettingsUpdate` (encoder) |
//! | [`error`] | `FileSettingsError` and sentinel types (`NibbleSlot`, `OverlapKind`, `ReservedByte`) |

pub mod access;
pub mod codec;
pub mod error;
pub mod sdm;

pub use access::{Access, AccessRights, CommMode, CtrRetAccess, FileType};
pub use codec::{FileSettingsUpdate, FileSettingsView, MAX_CHANGE_FILE_SETTINGS_LEN};
pub use error::{FileSettingsError, NibbleSlot, OverlapKind, ReservedByte};
pub use sdm::{
    CryptoMode, EncFileData, EncLength, EncryptedContent, FileRead, MacWindow, Offset, PiccData,
    PlainMirror, ReadCtrFeatures, ReadCtrMirror, Sdm,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{File, KeyNumber};

    fn free_access_rights() -> AccessRights {
        AccessRights {
            read: Access::Free,
            write: Access::Free,
            read_write: Access::Free,
            change: Access::Free,
        }
    }

    fn std_access_rights() -> AccessRights {
        AccessRights {
            read: Access::Free,
            write: Access::Key(KeyNumber::Key0),
            read_write: Access::Key(KeyNumber::Key0),
            change: Access::Key(KeyNumber::Key0),
        }
    }

    /// AN12196 §5.4 Table 7 - `GetFileSettings` response for NDEF file with SDM
    /// (Key0 encrypted PICCData, Key0 file-read/MAC, free CTR-ret, enc file data).
    const AN12196_GET_FS_PAYLOAD: &[u8] = &[
        0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xD1, 0xFE, 0x00, 0x1F, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x6A, 0x00, 0x00,
    ];

    #[test]
    fn decode_an12196_get_file_settings() {
        let fs = FileSettingsView::decode(AN12196_GET_FS_PAYLOAD).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.access_rights, free_access_rights());

        let sdm = fs.sdm.expect("SDM enabled");
        assert_eq!(
            sdm.picc_data(),
            PiccData::Encrypted {
                key: KeyNumber::Key0,
                offset: Offset(0x1F),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Free,
                }),
            }
        );
        let fr = sdm.file_read().expect("file_read");
        assert_eq!(fr.key(), KeyNumber::Key0);
        assert_eq!(fr.window().input, Offset(0x44));
        assert_eq!(fr.window().mac, Offset(0x6A));
        let enc = fr.enc().expect("enc");
        assert_eq!(enc.start, Offset(0x44));
        assert_eq!(enc.length, EncLength(0x20));
        assert_eq!(sdm.tamper_status(), None);
    }

    /// AN12196 §5.9 Table 18 - `ChangeFileSettings` CmdData for NDEF file.
    /// Encrypted PICCData Key2, SDM read Key1, no enc-file data, CTR-ret Key1.
    const AN12196_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0xC1, 0xF1, 0x21, 0x20, 0x00, 0x00, 0x43, 0x00, 0x00, 0x43, 0x00, 0x00,
    ];

    fn an12196_change_patch() -> FileSettingsUpdate {
        let sdm = Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key2,
                offset: Offset(0x20),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Key(KeyNumber::Key1),
                }),
            },
            Some(FileRead::MacOnly {
                key: KeyNumber::Key1,
                window: MacWindow {
                    input: Offset(0x43),
                    mac: Offset(0x43),
                },
            }),
            None,
            CryptoMode::Aes,
        )
        .unwrap();
        FileSettingsUpdate::new(CommMode::Plain, std_access_rights()).with_sdm(sdm)
    }

    #[test]
    fn encode_an12196_change_file_settings() {
        let patch = an12196_change_patch();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], AN12196_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings() {
        // Decode GET, convert to patch, re-encode, compare to expected CHANGE payload.
        let fs = FileSettingsView::decode(AN12196_GET_FS_PAYLOAD).unwrap();
        let patch = fs.into_update();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).unwrap();
        // Expected CHANGE payload: FileOption(1) + AR(2) + SDM block(…)
        let mut expected = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        expected[0] = AN12196_GET_FS_PAYLOAD[1]; // FileOption
        expected[1..3].copy_from_slice(&AN12196_GET_FS_PAYLOAD[2..4]); // AccessRights
        let sdm_len = AN12196_GET_FS_PAYLOAD.len() - 7;
        expected[3..3 + sdm_len].copy_from_slice(&AN12196_GET_FS_PAYLOAD[7..]);
        assert_eq!(&buf[..n], &expected[..3 + sdm_len]);
    }

    #[test]
    fn buffer_too_short_on_decode() {
        assert!(matches!(
            FileSettingsView::decode(&[0x00, 0x00]),
            Err(FileSettingsError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn rejects_enc_outside_mac_window() {
        // enc range must be inside the MAC window.
        let enc = EncFileData {
            start: Offset(0x10),
            length: EncLength::new(32).unwrap(),
        };
        let window = MacWindow {
            input: Offset(0x10),
            mac: Offset(0x20), // mac < enc_end(0x30) → error
        };
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key2,
            offset: Offset(0x00),
            content: EncryptedContent::Both(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        };
        let err = Sdm::try_new(
            picc,
            Some(FileRead::MacAndEnc {
                key: KeyNumber::Key1,
                window,
                enc,
            }),
            None,
            CryptoMode::Aes,
        )
        .unwrap_err();
        assert_eq!(err, FileSettingsError::EncOutsideMacWindow);
    }

    #[test]
    fn sdm_is_const_constructable() {
        // Verify Sdm::try_new can be used in const context.
        const SDM: Sdm = match Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key2,
                offset: Offset(0x20),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Key(KeyNumber::Key1),
                }),
            },
            Some(FileRead::MacOnly {
                key: KeyNumber::Key1,
                window: MacWindow {
                    input: Offset(0x43),
                    mac: Offset(0x43),
                },
            }),
            None,
            CryptoMode::Aes,
        ) {
            Ok(s) => s,
            Err(_) => panic!("const SDM construction failed"),
        };
        assert_eq!(SDM.file_read().unwrap().key(), KeyNumber::Key1);
    }

    #[test]
    fn try_new_enables_tt_status_mirroring() {
        // TT-only without MAC - valid configuration.
        let sdm = Sdm::try_new(
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) }),
            None,
            Some(Offset(0x2E)),
            CryptoMode::Aes,
        )
        .unwrap();
        assert_eq!(sdm.tamper_status(), Some(Offset(0x2E)));
        assert!(sdm.file_read().is_none());
    }

    // TT_CHANGE_FS_PAYLOAD: UID mirror at 0x20, TT at 0x2E (non-overlapping; UID is 14 ASCII bytes).
    const TT_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x2E, 0x00, 0x00,
    ];

    fn tt_change_patch() -> FileSettingsUpdate {
        let sdm = Sdm::try_new(
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) }),
            None,
            Some(Offset(0x2E)),
            CryptoMode::Aes,
        )
        .unwrap();
        FileSettingsUpdate::new(CommMode::Plain, std_access_rights()).with_sdm(sdm)
    }

    #[test]
    fn encode_change_file_settings_with_tt_status() {
        let patch = tt_change_patch();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings_with_tt_status() {
        // GetFileSettings payload: uid mirror at 0x20, TT at 0x2E (non-overlapping).
        let payload = [
            0x00, 0x40, 0x00, 0xE0, 0x40, 0x00, 0x00, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x2E,
            0x00, 0x00,
        ];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        let sdm = fs.sdm.as_ref().expect("sdm");
        assert_eq!(
            sdm.picc_data(),
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) })
        );
        assert_eq!(sdm.tamper_status(), Some(Offset(0x2E)));

        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.into_update().encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn clear_tt_with_sdm_mac_keeps_meta_disabled() {
        // PiccData::None + MAC only (TT offset mirrored, no PICC metadata).
        let sdm = Sdm::try_new(
            PiccData::None,
            Some(FileRead::MacOnly {
                key: KeyNumber::Key0,
                window: MacWindow {
                    input: Offset(0x12),
                    mac: Offset(0x1C),
                },
            }),
            Some(Offset(0x17)),
            CryptoMode::Aes,
        )
        .unwrap();
        let patch = FileSettingsUpdate::new(CommMode::Plain, std_access_rights()).with_sdm(sdm);
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                0x40, 0x00, 0xE0, 0x09, 0xFF, 0xF0, 0x17, 0x00, 0x00, 0x12, 0x00, 0x00, 0x1C, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn read_ctr_limit_sentinel_decodes_as_none() {
        // SDM with read_ctr_limit_enabled=1 but value = 0x00FF_FFFF (sentinel = unlimited).
        // Uses Encrypted PICCData with Both content and limit enabled.
        // FileType=0, FileOption=0x40, AR=0xEEEE, FileSize=0x000100,
        // SDMOptions=0xF1 (uid+rctr+limit+ascii), SDMAR=meta=Key0,file=F,rfu=F,ctr=F → 0x0FFF LE = FF 0F
        // enc_picc_offset=0x1F, then sentinel 0xFFFFFF.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xF1, 0xFF,
            0x0F, // SDMOptions (uid+rctr+limit+ascii), SDMAR LE (meta=0,file=F,rfu=F,ctr=F)
            0x1F, 0x00, 0x00, // encrypted picc offset
            0xFF, 0xFF, 0xFF, // sentinel limit → None
        ];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        let sdm = fs.sdm.expect("sdm");
        assert_eq!(sdm.picc_data().read_ctr_limit(), None);
    }

    // -- Negative-path tests: Sdm::try_new validation ---------------------------

    fn both_picc(off: u32) -> PiccData {
        PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(off),
            content: EncryptedContent::Both(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        }
    }

    fn plain_both(uid: u32, rctr: u32) -> PiccData {
        PiccData::Plain(PlainMirror::Both {
            uid: Offset(uid),
            read_ctr: ReadCtrMirror {
                offset: Offset(rctr),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        })
    }

    fn mac_only(input: u32, mac: u32) -> Option<FileRead> {
        Some(FileRead::MacOnly {
            key: KeyNumber::Key0,
            window: MacWindow {
                input: Offset(input),
                mac: Offset(mac),
            },
        })
    }

    fn mac_and_enc(input: u32, mac: u32, enc_start: u32, enc_len: u32) -> Option<FileRead> {
        Some(FileRead::MacAndEnc {
            key: KeyNumber::Key0,
            window: MacWindow {
                input: Offset(input),
                mac: Offset(mac),
            },
            enc: EncFileData {
                start: Offset(enc_start),
                length: EncLength::new(enc_len).unwrap(),
            },
        })
    }

    #[test]
    fn rejects_mac_input_after_mac() {
        let err =
            Sdm::try_new(PiccData::None, mac_only(0x20, 0x10), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(err, FileSettingsError::MacInputAfterMac);
    }

    #[test]
    fn rejects_enc_requires_both_mirrors_uid_only() {
        // MacAndEnc but picc_data has only UID, no RCtr.
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(0),
            content: EncryptedContent::Uid,
        };
        let err =
            Sdm::try_new(picc, mac_and_enc(0, 0x40, 0, 32), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(err, FileSettingsError::EncRequiresBothMirrors);
    }

    #[test]
    fn rejects_enc_requires_both_mirrors_rctr_only() {
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(0),
            content: EncryptedContent::RCtr(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        };
        let err =
            Sdm::try_new(picc, mac_and_enc(0, 0x40, 0, 32), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(err, FileSettingsError::EncRequiresBothMirrors);
    }

    #[test]
    fn rejects_overlap_uid_and_rctr() {
        // UID at 0x10 (14 bytes), RCtr at 0x15 (overlaps UID).
        let picc = plain_both(0x10, 0x15);
        let err = Sdm::try_new(picc, None, None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndRCtr)
        );
    }

    #[test]
    fn rejects_overlap_uid_and_tamper() {
        // UID at 0x10 (14 bytes), TT at 0x1A - inside UID span.
        let picc = PiccData::Plain(PlainMirror::Uid { uid: Offset(0x10) });
        let err = Sdm::try_new(picc, None, Some(Offset(0x1A)), CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndTamper)
        );
    }

    #[test]
    fn rejects_overlap_rctr_and_tamper() {
        // RCtr at 0x10 (6 bytes), TT at 0x14 - overlaps RCtr.
        let picc = PiccData::Plain(PlainMirror::RCtr {
            read_ctr: ReadCtrMirror {
                offset: Offset(0x10),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        });
        let err = Sdm::try_new(picc, None, Some(Offset(0x14)), CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::RCtrAndTamper)
        );
    }

    #[test]
    fn rejects_overlap_uid_and_mac() {
        // UID at 0x10 (14 bytes), MAC window mac-offset at 0x15 - inside UID span.
        let picc = PiccData::Plain(PlainMirror::Uid { uid: Offset(0x10) });
        let err = Sdm::try_new(picc, mac_only(0x00, 0x15), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndMac)
        );
    }

    #[test]
    fn rejects_overlap_rctr_and_mac() {
        // RCtr at 0x10 (6 bytes), MAC at 0x12 - inside RCtr span.
        let picc = PiccData::Plain(PlainMirror::RCtr {
            read_ctr: ReadCtrMirror {
                offset: Offset(0x10),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        });
        let err = Sdm::try_new(picc, mac_only(0x00, 0x12), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::RCtrAndMac)
        );
    }

    #[test]
    fn rejects_overlap_tamper_and_mac() {
        // TT at 0x10 (2 bytes), MAC at 0x11 - overlaps TT.
        let err = Sdm::try_new(
            PiccData::None,
            mac_only(0x00, 0x11),
            Some(Offset(0x10)),
            CryptoMode::Aes,
        )
        .unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::TamperAndMac)
        );
    }

    #[test]
    fn rejects_overlap_enc_and_uid() {
        // Plain UID at 0x10, ENC starts at 0x15 (overlaps UID's 14-byte span 0x10..0x1E).
        // Use plain_both so validation (requires both uid+rctr) passes.
        let picc = plain_both(0x10, 0x60);
        let err =
            Sdm::try_new(picc, mac_and_enc(0, 0x80, 0x15, 32), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::EncAndUid)
        );
    }

    #[test]
    fn rejects_overlap_enc_and_rctr() {
        // Plain UID at 0x00, RCtr at 0x20 (6 bytes: 0x20..0x26).
        // ENC at 0x1E..0x3E overlaps RCtr.
        // Use plain_both so validation passes.
        let picc = plain_both(0x00, 0x20);
        let err =
            Sdm::try_new(picc, mac_and_enc(0, 0x80, 0x1E, 32), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::EncAndRCtr)
        );
    }

    #[test]
    fn rejects_tamper_in_ciphertext_half() {
        // ENC at 0x20..0x40 (32 bytes); plaintext half = 0x20..0x30.
        // TT at 0x30 - exactly at the start of the ciphertext half.
        let err = Sdm::try_new(
            both_picc(0),
            mac_and_enc(0, 0x80, 0x20, 32),
            Some(Offset(0x30)),
            CryptoMode::Aes,
        )
        .unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::TamperInCiphertextHalf)
        );
    }

    #[test]
    fn tamper_at_last_byte_of_plaintext_half_is_ok() {
        // ENC at 0x20..0x40 (32 bytes); plaintext half ends at 0x30.
        // TT (2 bytes) at 0x2E - fits entirely in 0x2E..0x30, within the plain half.
        Sdm::try_new(
            both_picc(0),
            mac_and_enc(0, 0x80, 0x20, 32),
            Some(Offset(0x2E)),
            CryptoMode::Aes,
        )
        .unwrap();
    }

    #[test]
    fn rejects_picc_blob_overlapping_mac_aes() {
        // AES picc blob at 0x00..0x20 (32 bytes), MAC at 0x10 — inside the blob.
        let picc = both_picc(0x00);
        let err = Sdm::try_new(picc, mac_only(0x00, 0x10), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::PiccAndMac)
        );
    }

    #[test]
    fn rejects_picc_blob_overlapping_mac_lrp() {
        // LRP picc blob at 0x00..0x30 (48 bytes), MAC at 0x28 — inside the blob.
        let picc = both_picc(0x00);
        let err = Sdm::try_new(picc, mac_only(0x00, 0x28), None, CryptoMode::Lrp).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::PiccAndMac)
        );
    }

    #[test]
    fn rejects_picc_blob_overlapping_tamper() {
        // AES picc blob at 0x00..0x20, TT at 0x10.
        let picc = both_picc(0x00);
        let err = Sdm::try_new(picc, None, Some(Offset(0x10)), CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::PiccAndTamper)
        );
    }

    #[test]
    fn rejects_picc_blob_overlapping_enc_file_data() {
        // AES picc blob at 0x00..0x20, enc file data at 0x10..0x30 — overlaps blob.
        let picc = both_picc(0x00);
        let err =
            Sdm::try_new(picc, mac_and_enc(0, 0x80, 0x10, 32), None, CryptoMode::Aes).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::PiccAndEnc)
        );
    }

    #[test]
    fn picc_blob_just_before_mac_is_ok() {
        // AES picc blob at 0x00..0x20 (32 bytes), MAC at exactly 0x20 — no overlap.
        let picc = both_picc(0x00);
        Sdm::try_new(picc, mac_only(0x00, 0x20), None, CryptoMode::Aes).unwrap();
    }

    #[test]
    fn lrp_blob_just_before_mac_is_ok() {
        // LRP picc blob at 0x00..0x30 (48 bytes), MAC at exactly 0x30 — no overlap.
        let picc = both_picc(0x00);
        Sdm::try_new(picc, mac_only(0x00, 0x30), None, CryptoMode::Lrp).unwrap();
    }

    // -- Negative-path tests: FileSettingsView::decode reserved-bit checks ------

    fn base_payload() -> [u8; 7] {
        // StandardData, FileOption=0x00 (no SDM, plain), AR=0xEEEE, size=256.
        [0x00, 0x00, 0xEE, 0xEE, 0x00, 0x01, 0x00]
    }

    #[test]
    fn decode_rejects_file_option_reserved_bits() {
        let mut p = base_payload();
        // Byte 1 = FileOption; set bit 2 (RFU).
        p[1] = 0x04;
        assert!(matches!(
            FileSettingsView::decode(&p),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::FileOption,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_sdm_options_ascii_bit_clear() {
        // FileOption = 0x40 (SDM enabled, plain). SDMOptions bit 0 must be 1.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00,
            0x00, // SDMOptions: bit 0 = 0 (binary mode, RFU) → error
            0xFF, 0x0F, // SDMAR
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::SdmOptions,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_sdm_access_rights_high_nibble_not_f() {
        // FileOption=0x40, SDMOptions=0x01 (ascii-only, no mirrors), SDMAR[0] high nibble ≠ F.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0x01, // SDMOptions: ascii only
            0xAF, // SDMAR[0]: high nibble = A ≠ F → error
            0xFF, // SDMAR[1]
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::SdmAccessRights0,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_s19_ctr_ret_set_without_rctr_mirror() {
        // SDMOptions = 0x81: uid_mirror=1 (bit7), rctr_mirror=0 (bit6), ascii=1 (bit0).
        // AR bytes: v = u16::from_le_bytes([byte0, byte1]).
        //   ctr_ret_nibble = v & 0xF = byte0 low nibble → Key0 (= 0x0) to trigger validation error.
        //   validation requires byte0 high nibble = F → byte0 = 0xF0.
        //   byte1 = 0xFF (meta=F NoAccess, file=F NoAccess).
        // No uid offset is read (meta_plain = false since picc_meta_nibble = F ≠ E).
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00,
            0x81, // SDMOptions: uid_mirror=1, rctr_mirror=0, ascii=1
            0xF0, // SDMAR byte0: RFU nibble=F, ctr_ret nibble=0 (Key0)
            0xFF, // SDMAR byte1: picc_meta nibble=F, file_read nibble=F
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::InvalidSdmFlags)
        ));
    }

    #[test]
    fn decode_factory_file_settings_cc() {
        let payload = [0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 32);
        assert_eq!(fs.access_rights.read, Access::Free);
        assert_eq!(fs.access_rights.write, Access::Key(KeyNumber::Key0));
        assert_eq!(fs.access_rights.read_write, Access::Key(KeyNumber::Key0));
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }

    #[test]
    fn decode_factory_file_settings_ndef() {
        let payload = [0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.access_rights.read, Access::Free);
        assert_eq!(fs.access_rights.write, Access::Free);
        assert_eq!(fs.access_rights.read_write, Access::Free);
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }

    #[test]
    fn decode_factory_file_settings_proprietary() {
        let payload = [0x00, 0x03, 0x30, 0x23, 0x80, 0x00, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Full);
        assert_eq!(fs.file_size, 128);
        assert_eq!(fs.access_rights.read, Access::Key(KeyNumber::Key2));
        assert_eq!(fs.access_rights.write, Access::Key(KeyNumber::Key3));
        assert_eq!(fs.access_rights.read_write, Access::Key(KeyNumber::Key3));
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }

    #[test]
    fn factory_matches_decoded_cc() {
        let payload = [0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00];
        assert_eq!(
            FileSettingsView::factory(File::CapabilityContainer),
            FileSettingsView::decode(&payload).unwrap()
        );
    }

    #[test]
    fn factory_matches_decoded_ndef() {
        let payload = [0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00];
        assert_eq!(
            FileSettingsView::factory(File::Ndef),
            FileSettingsView::decode(&payload).unwrap()
        );
    }

    #[test]
    fn factory_matches_decoded_proprietary() {
        let payload = [0x00, 0x03, 0x30, 0x23, 0x80, 0x00, 0x00];
        assert_eq!(
            FileSettingsView::factory(File::Proprietary),
            FileSettingsView::decode(&payload).unwrap()
        );
    }
}
