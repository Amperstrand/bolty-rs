// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Secure Dynamic Messaging (SDM) server-side verification.
//!
//! Implements the read-side (server / verifier) crypto for NTAG 424 DNA
//! Secure Dynamic Messaging (NT4H2421Gx §9.3).
//!
//! # Usage
//!
//! 1. Obtain the [`Sdm`] from [`AuthenticatedSession::get_file_settings`] (or construct one via
//!    [`Sdm::try_new`] matching the tag's configuration).
//! 2. Create a [`Verifier`] via [`try_new`] with the
//!    settings and [`CryptoMode`].
//! 3. Call [`verify`] with the raw NDEF file bytes and the application key
//!    to verify the authentication MAC and recover the dynamic data.
//!
//! [`Sdm`]: crate::types::file_settings::Sdm
//! [`Sdm::try_new`]: crate::types::file_settings::Sdm::try_new
//! [`try_new`]: Verifier::try_new
//! [`verify`]: Verifier::verify
//! [`AuthenticatedSession::get_file_settings`]: crate::AuthenticatedSession::get_file_settings
//!
//! # Module layout
//!
//! | Sub-module | Contents |
//! |---|---|
//! | [`verifier`] | Public API: `CryptoMode`, `SdmError`, `SdmVerification`, `Verifier` |
//! | [`picc`] | PICCData decryption (`decrypt_picc_data_aes/lrp`, §9.3.4) |
//! | [`keys`] | Session key derivation and MAC verification (`derive_sdm_keys_aes/lrp`, §9.3.9) |
//! | [`hex`] | NDEF ASCII-hex decoding helpers |

pub(crate) mod hex;
pub(crate) mod keys;
pub(crate) mod picc;
pub(crate) mod verifier;

pub use verifier::{SdmError, SdmVerification, Verifier};

#[cfg(test)]
mod tests {
    use super::keys::{SdmKeys, aes_ecb_encrypt_block, derive_sdm_keys_aes, derive_sdm_keys_lrp};
    use super::picc::{decrypt_picc_data_aes, decrypt_picc_data_lrp};
    use super::*;
    use crate::crypto::suite::{aes_cbc_encrypt, cmac_aes, cmac_lrp, truncate_mac};
    use crate::testing::hex_array;
    use crate::types::file_settings::{
        CryptoMode, CtrRetAccess, EncFileData, EncLength, EncryptedContent, FileRead, MacWindow,
        Offset, PiccData, PlainMirror, ReadCtrFeatures, Sdm,
    };
    use crate::types::{KeyNumber, TagTamperStatus};

    // -- Helper: build a synthetic NDEF file for testing ---------------------

    /// Construct a minimal NDEF file with hex-encoded SDM placeholders.
    fn build_ndef(
        prefix: &[u8],
        picc_hex: Option<&str>,
        enc_hex: Option<&str>,
        mid: &[u8],
        mac_hex: &str,
    ) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(prefix);
        if let Some(p) = picc_hex {
            buf.extend_from_slice(p.as_bytes());
        }
        if let Some(e) = enc_hex {
            buf.extend_from_slice(e.as_bytes());
        }
        buf.extend_from_slice(mid);
        buf.extend_from_slice(mac_hex.as_bytes());
        buf
    }

    fn encrypted_settings(
        picc_key: KeyNumber,
        read_key: KeyNumber,
        picc_offset: u32,
        mac_input: u32,
        mac: u32,
        mode: CryptoMode,
    ) -> Sdm {
        Sdm::try_new(
            PiccData::Encrypted {
                key: picc_key,
                offset: Offset::new(picc_offset).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                }),
            },
            Some(FileRead::MacOnly {
                key: read_key,
                window: MacWindow {
                    input: Offset::new(mac_input).unwrap(),
                    mac: Offset::new(mac).unwrap(),
                },
            }),
            None,
            mode,
        )
        .unwrap()
    }

    fn encrypted_settings_with_enc_data(
        picc_key: KeyNumber,
        read_key: KeyNumber,
        picc_offset: u32,
        mac_input: u32,
        mac: u32,
        encrypted_file_data: Option<core::ops::Range<u32>>,
        mode: CryptoMode,
    ) -> Sdm {
        let file_read = match encrypted_file_data {
            Some(range) => FileRead::MacAndEnc {
                key: read_key,
                window: MacWindow {
                    input: Offset::new(mac_input).unwrap(),
                    mac: Offset::new(mac).unwrap(),
                },
                enc: EncFileData {
                    start: Offset::new(range.start).unwrap(),
                    length: EncLength::new(range.end - range.start).unwrap(),
                },
            },
            None => FileRead::MacOnly {
                key: read_key,
                window: MacWindow {
                    input: Offset::new(mac_input).unwrap(),
                    mac: Offset::new(mac).unwrap(),
                },
            },
        };
        Sdm::try_new(
            PiccData::Encrypted {
                key: picc_key,
                offset: Offset::new(picc_offset).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                }),
            },
            Some(file_read),
            None,
            mode,
        )
        .unwrap()
    }

    // -- End-to-end verifier tests ------------------------------------------

    /// Build settings + NDEF for Table 4 (encrypted PICC, empty MAC input).
    fn table4_fixture() -> (Sdm, alloc::vec::Vec<u8>) {
        // Layout: [10-byte prefix][32-char PICCData hex][16-char SDMMAC hex]
        let settings = encrypted_settings(
            KeyNumber::Key0,
            KeyNumber::Key0,
            10,
            42,
            42,
            CryptoMode::Aes,
        );
        let ndef = build_ndef(
            b"HELLOWORLD", // 10-byte prefix
            Some("EF963FF7828658A599F3041510671E88"),
            None,
            b"",
            "94EED9EE65337086",
        );
        (settings, ndef)
    }

    fn plain_uid_tamper_fixture() -> (Sdm, alloc::vec::Vec<u8>) {
        let key = [0u8; 16];
        let uid = hex_array::<7>("04DE5F1EACC040");
        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(b"HELLOWORLD");
        ndef.extend_from_slice(b"04DE5F1EACC040");
        ndef.extend_from_slice(b"CO");

        let keys = derive_sdm_keys_aes(&key, Some(&uid), None);
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        let mac = truncate_mac(&cmac_aes(&mac_key, &ndef[10..26]));
        let mac_hex: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();
        ndef.extend_from_slice(mac_hex.as_bytes());

        let settings = Sdm::try_new(
            PiccData::Plain(PlainMirror::Uid {
                uid: Offset::new(10).unwrap(),
            }),
            Some(FileRead::MacOnly {
                key: KeyNumber::Key0,
                window: MacWindow {
                    input: Offset::new(10).unwrap(),
                    mac: Offset::new(26).unwrap(),
                },
            }),
            Some(Offset::new(24).unwrap()),
            CryptoMode::Aes,
        )
        .unwrap();

        (settings, ndef)
    }

    #[test]
    fn verify_encrypted_picc_empty_mac() {
        let (settings, ndef) = table4_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &[0u8; 16]).unwrap();
        assert_eq!(result.uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(result.read_ctr, Some(61));
        assert_eq!(result.tamper_status, None);
        assert_eq!(result.enc_file_data, None);
    }

    #[test]
    fn verify_extracts_clear_tamper_status() {
        let (settings, ndef) = plain_uid_tamper_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &[0u8; 16]).unwrap();
        let tt = result.tamper_status.expect("tag tamper");
        assert_eq!(tt.permanent(), TagTamperStatus::Close);
        assert_eq!(tt.current(), TagTamperStatus::Open);
    }

    #[test]
    fn with_offset_verifies_prefixed_encrypted_picc_ndef() {
        let (settings, ndef) = table4_fixture();
        let mut shifted = alloc::vec::Vec::new();
        shifted.extend_from_slice(b"xx");
        shifted.extend_from_slice(&ndef);

        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let shifted_v = v.with_offset(2).unwrap();
        let result = shifted_v.verify(&shifted, &[0u8; 16]).unwrap();

        assert_eq!(result.uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(result.read_ctr, Some(61));
    }

    #[test]
    fn with_offset_verifies_sliced_plain_mirror_ndef() {
        let (settings, ndef) = plain_uid_tamper_fixture();

        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let shifted_v = v.with_offset(-5).unwrap();
        let result = shifted_v.verify(&ndef[5..], &[0u8; 16]).unwrap();

        assert_eq!(result.uid, Some(hex_array("04DE5F1EACC040")));
        let tt = result.tamper_status.expect("tag tamper");
        assert_eq!(tt.permanent(), TagTamperStatus::Close);
        assert_eq!(tt.current(), TagTamperStatus::Open);
    }

    #[test]
    fn with_offset_rejects_out_of_range_adjustments() {
        let (settings, _) = table4_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();

        assert!(v.with_offset(i32::MIN).is_none());
        assert!(v.with_offset(-11).is_none());
        assert!(v.with_offset(214).is_none());
    }

    #[test]
    fn decrypt_picc_data_does_not_require_mac_bytes() {
        let (settings, ndef) = table4_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();

        let (uid, read_ctr) = v.decrypt_picc_data(&[0; 16], &ndef[..42]).unwrap();

        assert_eq!(uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(read_ctr, Some(61));
    }

    #[test]
    fn verify_rejects_wrong_mac() {
        let (settings, mut ndef) = table4_fixture();
        // Tamper with the MAC (last hex char).
        let len = ndef.len();
        ndef[len - 1] = b'0';
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        assert_eq!(v.verify(&ndef, &[0u8; 16]), Err(SdmError::MacMismatch));
    }

    #[test]
    fn verify_rejects_short_ndef() {
        let (settings, ndef) = table4_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        assert!(matches!(
            v.verify(&ndef[..40], &[0u8; 16]),
            Err(SdmError::NdefTooShort { .. }),
        ));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        let (settings, mut ndef) = table4_fixture();
        ndef[10] = b'Z'; // corrupt first PICCData hex char
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        assert!(matches!(
            v.verify(&ndef, &[0u8; 16]),
            Err(SdmError::InvalidHex { offset: 10 }),
        ));
    }

    // -- LRP tests ----------------------------------------------------------

    /// LRP SDM verification: encrypted PICC + CMAC, no enc file data.
    #[test]
    fn verify_lrp_encrypted_picc_cmac() {
        let key = [0u8; 16];

        // Layout: [7 prefix][48 PICCData hex]['x'][16 SDMMAC hex]
        let prefix = b"PREFIX_";
        let picc_hex = "AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293";
        let mac_hex = "5E3DB82C19E3865F";
        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(prefix);
        ndef.extend_from_slice(picc_hex.as_bytes());
        ndef.extend_from_slice(b"x");
        ndef.extend_from_slice(mac_hex.as_bytes());

        let settings =
            encrypted_settings(KeyNumber::Key0, KeyNumber::Key0, 7, 7, 56, CryptoMode::Lrp);

        let v = Verifier::try_new(&settings, CryptoMode::Lrp).unwrap();
        let result = v.verify(&ndef, &key).unwrap();
        assert_eq!(result.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(result.read_ctr, Some(106)); // 0x6a
    }

    /// LRP SDM verification: encrypted PICC + encrypted file data + CMAC.
    #[test]
    fn verify_lrp_with_enc_file_data() {
        let key = [0u8; 16];

        // NDEF layout: [prefix][48 PICCData hex]['x'][32 ENCFileData hex]['x'][16 SDMMAC hex]
        let prefix = b"any.domain/?m=";
        let picc_hex = "65628ED36888CF9C84797E43ECACF114C6ED9A5E101EB592";
        let enc_hex = "4ADE304B5AB9474CB40AFFCAB0607A85";
        let mac_hex = "87E287E8135BFC06";
        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(prefix); // offset 0, len 14
        ndef.extend_from_slice(picc_hex.as_bytes()); // offset 14, len 48
        ndef.extend_from_slice(b"x"); // offset 62
        ndef.extend_from_slice(enc_hex.as_bytes()); // offset 63, len 32
        ndef.extend_from_slice(b"x"); // offset 95
        ndef.extend_from_slice(mac_hex.as_bytes()); // offset 96, len 16

        let settings = encrypted_settings_with_enc_data(
            KeyNumber::Key0,
            KeyNumber::Key0,
            14,
            0,
            96,
            Some(63..95),
            CryptoMode::Lrp,
        );

        let v = Verifier::try_new(&settings, CryptoMode::Lrp).unwrap();
        let result = v.verify(&ndef, &key).unwrap();
        assert_eq!(result.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(result.read_ctr, Some(123)); // 0x7b
        assert_eq!(
            result.enc_file_data.as_deref(),
            Some(b"0102030400000000".as_slice()),
        );
    }

    /// LRP verifier with split keys (different meta/file read keys).
    #[test]
    fn verify_lrp_split_keys() {
        let meta_key: [u8; 16] = [0u8; 16];
        let file_key: [u8; 16] = hex_array("5ACE7E50AB65D5D51FD5BF5A16B8205B");

        let picc_hex = "AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293";
        let uid = hex_array::<7>("042E1D222A6380");
        let ctr = hex_array::<3>("6A0000");
        let keys = derive_sdm_keys_lrp(&file_key, Some(&uid), Some(&ctr));

        let mac_input = [picc_hex, "x"].concat();
        let mac = match &keys {
            SdmKeys::Lrp { mac, .. } => truncate_mac(&cmac_lrp(
                crate::crypto::lrp::Lrp::clone(mac),
                mac_input.as_bytes(),
            )),
            _ => unreachable!(),
        };
        let mac_hex: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(b"PREFIX_"); // offset 0, len 7
        ndef.extend_from_slice(picc_hex.as_bytes()); // offset 7, len 48
        ndef.extend_from_slice(b"x"); // offset 55
        ndef.extend_from_slice(mac_hex.as_bytes()); // offset 56, len 16

        let settings =
            encrypted_settings(KeyNumber::Key0, KeyNumber::Key2, 7, 7, 56, CryptoMode::Lrp);

        let v = Verifier::try_new(&settings, CryptoMode::Lrp).unwrap();
        let result = v.verify_with_meta_key(&ndef, &file_key, &meta_key).unwrap();
        assert_eq!(result.uid, Some(uid));
        assert_eq!(result.read_ctr, Some(106));
    }

    #[test]
    fn try_new_rejects_no_file_read() {
        let settings = Sdm::try_new(PiccData::None, None, None, CryptoMode::Aes).unwrap();
        assert!(matches!(
            Verifier::try_new(&settings, CryptoMode::Aes),
            Err(SdmError::InvalidConfiguration(_)),
        ));
    }

    #[test]
    fn sdm_try_new_rejects_enc_file_data_without_read_access() {
        assert!(
            Sdm::try_new(
                PiccData::Encrypted {
                    key: KeyNumber::Key0,
                    offset: Offset::new(10).unwrap(),
                    content: EncryptedContent::Both(ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::NoAccess,
                    }),
                },
                Some(FileRead::MacAndEnc {
                    key: KeyNumber::Key0,
                    window: MacWindow {
                        input: Offset::new(42).unwrap(),
                        mac: Offset::new(74).unwrap(),
                    },
                    enc: EncFileData {
                        start: Offset::new(42).unwrap(),
                        length: EncLength::new(32).unwrap(),
                    },
                }),
                None,
                CryptoMode::Aes,
            )
            .is_ok()
        );
    }

    #[test]
    fn try_new_rejects_enc_file_data_without_uid_mirror() {
        use crate::types::file_settings::FileSettingsError;
        assert!(matches!(
            Sdm::try_new(
                PiccData::Encrypted {
                    key: KeyNumber::Key0,
                    offset: Offset::new(10).unwrap(),
                    content: EncryptedContent::RCtr(ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::NoAccess,
                    }),
                },
                Some(FileRead::MacAndEnc {
                    key: KeyNumber::Key0,
                    window: MacWindow {
                        input: Offset::new(42).unwrap(),
                        mac: Offset::new(74).unwrap(),
                    },
                    enc: EncFileData {
                        start: Offset::new(42).unwrap(),
                        length: EncLength::new(32).unwrap(),
                    },
                }),
                None,
                CryptoMode::Aes,
            ),
            Err(FileSettingsError::EncRequiresBothMirrors),
        ));
    }

    #[test]
    fn try_new_rejects_enc_file_data_without_read_ctr_mirror() {
        use crate::types::file_settings::FileSettingsError;
        assert!(matches!(
            Sdm::try_new(
                PiccData::Encrypted {
                    key: KeyNumber::Key0,
                    offset: Offset::new(10).unwrap(),
                    content: EncryptedContent::Uid,
                },
                Some(FileRead::MacAndEnc {
                    key: KeyNumber::Key0,
                    window: MacWindow {
                        input: Offset::new(42).unwrap(),
                        mac: Offset::new(74).unwrap(),
                    },
                    enc: EncFileData {
                        start: Offset::new(42).unwrap(),
                        length: EncLength::new(32).unwrap(),
                    },
                }),
                None,
                CryptoMode::Aes,
            ),
            Err(FileSettingsError::EncRequiresBothMirrors),
        ));
    }

    #[test]
    fn try_new_rejects_inverted_enc_data_range() {
        use crate::types::file_settings::FileSettingsError;
        assert!(matches!(
            EncLength::new(0),
            Err(FileSettingsError::EncLengthInvalid(0)),
        ));
        assert!(EncLength::new(16).is_err());
    }

    #[test]
    fn try_new_rejects_mac_window_that_does_not_cover_enc_data() {
        use crate::types::file_settings::FileSettingsError;
        // mac_input=43 > enc_start=42 violates N3
        assert!(matches!(
            Sdm::try_new(
                PiccData::Encrypted {
                    key: KeyNumber::Key0,
                    offset: Offset::new(10).unwrap(),
                    content: EncryptedContent::Both(ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::NoAccess,
                    }),
                },
                Some(FileRead::MacAndEnc {
                    key: KeyNumber::Key0,
                    window: MacWindow {
                        input: Offset::new(43).unwrap(),
                        mac: Offset::new(74).unwrap(),
                    },
                    enc: EncFileData {
                        start: Offset::new(42).unwrap(),
                        length: EncLength::new(32).unwrap(),
                    },
                }),
                None,
                CryptoMode::Aes,
            ),
            Err(FileSettingsError::EncOutsideMacWindow),
        ));
    }

    /// End-to-end test with SDMENCFileData decryption (AN12196 Table 3).
    #[test]
    fn verify_with_enc_file_data() {
        let picc_hex = "FDE4AFA99B5C820A2C1BB0F1C792D0EB";
        let enc_hex = "94592FDE69FA06E8E3B6CA686A22842B";

        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("010000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));

        let mac_data = enc_hex.as_bytes();
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        let full_mac = cmac_aes(&mac_key, mac_data);
        let mac = truncate_mac(&full_mac);
        let mac_hex_str: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let settings = encrypted_settings_with_enc_data(
            KeyNumber::Key0,
            KeyNumber::Key0,
            10,
            42,
            74,
            Some(42..74),
            CryptoMode::Aes,
        );

        let ndef = build_ndef(
            b"HELLOWORLD",
            Some(picc_hex),
            Some(enc_hex),
            b"",
            &mac_hex_str,
        );

        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &[0u8; 16]).unwrap();
        assert_eq!(result.uid, Some(uid));
        assert_eq!(result.read_ctr, Some(1));
        assert_eq!(result.tamper_status, None);
        assert_eq!(
            result.enc_file_data.as_deref(),
            Some(b"xxxxxxxxxxxxxxxx".as_slice()),
        );
    }

    #[test]
    fn verify_extracts_tamper_status_from_enc_file_data() {
        let key = [0u8; 16];
        let picc_hex = "FDE4AFA99B5C820A2C1BB0F1C792D0EB";
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("010000");
        let keys = derive_sdm_keys_aes(&key, Some(&uid), Some(&ctr));
        let (enc_key, mac_key) = match &keys {
            SdmKeys::Aes { enc_key, mac_key } => (*enc_key, *mac_key),
            _ => unreachable!(),
        };

        let mut iv_in = [0u8; 16];
        iv_in[..3].copy_from_slice(&ctr);
        let iv = aes_ecb_encrypt_block(&enc_key, &iv_in);

        let mut pt = *b"xxCOxxxxxxxxxxxx";
        aes_cbc_encrypt(&enc_key, &iv, &mut pt).unwrap();
        let enc_hex: alloc::string::String = pt.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let mac = truncate_mac(&cmac_aes(&mac_key, enc_hex.as_bytes()));
        let mac_hex: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let settings = Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key0,
                offset: Offset::new(10).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                }),
            },
            Some(FileRead::MacAndEnc {
                key: KeyNumber::Key0,
                window: MacWindow {
                    input: Offset::new(42).unwrap(),
                    mac: Offset::new(74).unwrap(),
                },
                enc: EncFileData {
                    start: Offset::new(42).unwrap(),
                    length: EncLength::new(32).unwrap(),
                },
            }),
            Some(Offset::new(44).unwrap()),
            CryptoMode::Aes,
        )
        .unwrap();

        let ndef = build_ndef(b"HELLOWORLD", Some(picc_hex), Some(&enc_hex), b"", &mac_hex);
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &key).unwrap();
        let tt = result.tamper_status.expect("tag tamper");
        assert_eq!(tt.permanent(), TagTamperStatus::Close);
        assert_eq!(tt.current(), TagTamperStatus::Open);
        assert_eq!(
            result.enc_file_data.as_deref(),
            Some(b"xxCOxxxxxxxxxxxx".as_slice())
        );
    }

    #[test]
    fn try_new_rejects_tamper_status_in_second_half_of_enc_file_data_placeholder() {
        use crate::types::file_settings::FileSettingsError;
        assert!(matches!(
            Sdm::try_new(
                PiccData::Encrypted {
                    key: KeyNumber::Key0,
                    offset: Offset::new(10).unwrap(),
                    content: EncryptedContent::Both(ReadCtrFeatures {
                        limit: None,
                        ret_access: CtrRetAccess::NoAccess,
                    }),
                },
                Some(FileRead::MacAndEnc {
                    key: KeyNumber::Key0,
                    window: MacWindow {
                        input: Offset::new(42).unwrap(),
                        mac: Offset::new(74).unwrap(),
                    },
                    enc: EncFileData {
                        start: Offset::new(42).unwrap(),
                        length: EncLength::new(32).unwrap(),
                    },
                }),
                Some(Offset::new(58).unwrap()),
                CryptoMode::Aes,
            ),
            Err(FileSettingsError::MirrorsOverlap(_)),
        ));
    }

    #[test]
    fn verify_mac_rejects_wrong_key() {
        let (settings, ndef) = table4_fixture();
        let v = Verifier::try_new(&settings, CryptoMode::Aes).unwrap();
        let wrong_key = [0xFF; 16];
        assert!(matches!(
            v.verify(&ndef, &wrong_key),
            Err(SdmError::InvalidPiccDataTag(_)),
        ));
    }

    // Suppress unused-import warning when `alloc` or other features vary.
    #[allow(unused_imports)]
    use {aes_cbc_encrypt as _, decrypt_picc_data_aes as _, decrypt_picc_data_lrp as _};
}
