// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `ChangeFileSettings` command - NT4H2421Gx §10.7.1, AN12196 §5.9.

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{
        FileSettingsUpdate, ResponseCode, ResponseStatus,
        file_settings::MAX_CHANGE_FILE_SETTINGS_LEN,
    },
};

/// AES / LRP block size.
const BLOCK: usize = 16;

/// `MACt` trailer length (§9.1.3).
const MAC_LEN: usize = 8;

const CMD: u8 = 0x5F;

/// `ChangeFileSettings` (INS `5Fh`, NT4H2421Gx §10.7.1) in `CommMode.FULL`.
///
/// Authentication with the key indicated by the file's `Change` access
/// condition must be established before calling this. The command data
/// field (`FileOption || AccessRights [|| SDM block]`) is produced by
/// [`FileSettingsUpdate::encode`], then ISO/IEC 9797-1 Method 2 padded,
/// encrypted with `SesAuthENCKey`, and MAC'd together with the
/// `FileNo` header byte (§9.1.10 Figure 9).
///
/// The response is `MACt(8)` with SW `91 00`; no encrypted data is
/// returned. The response MAC is verified and `CmdCtr` is advanced on
/// success.
pub(crate) async fn change_file_settings<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    settings: &FileSettingsUpdate,
) -> Result<(), SessionError<T::Error>> {
    // Encode the ChangeFileSettings data payload.
    let mut raw = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
    let raw_len = settings
        .encode(&mut raw)
        .map_err(SessionError::FileSettings)?;

    // ISO/IEC 9797-1 Method 2 padding to a 16-byte boundary.
    let padded_len = (raw_len + 1).div_ceil(BLOCK) * BLOCK;
    let mut padded = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN + BLOCK];
    padded[..raw_len].copy_from_slice(&raw[..raw_len]);
    padded[raw_len] = 0x80;

    let ct = &mut padded[..padded_len];
    channel.encrypt_command(ct)?;

    let header = [file_no];
    let mac = channel.compute_cmd_mac(CMD, &header, ct);

    // APDU: 90 5F 00 00 <Lc> FileNo E(CmdData) MACt(8) 00.
    let lc = 1 + ct.len() + MAC_LEN;
    let apdu_len = 5 + lc + 1;
    let mut apdu = [0u8; 5 + 1 + MAX_CHANGE_FILE_SETTINGS_LEN + BLOCK + MAC_LEN + 1];
    apdu[..5].copy_from_slice(&[0x90, CMD, 0x00, 0x00, lc as u8]);
    apdu[5] = file_no;
    let mut pos = 6;
    apdu[pos..pos + ct.len()].copy_from_slice(ct);
    pos += ct.len();
    apdu[pos..pos + MAC_LEN].copy_from_slice(&mac);
    pos += MAC_LEN;
    apdu[pos] = 0x00; // Le
    debug_assert_eq!(pos + 1, apdu_len);

    let resp = transport.transmit(&apdu[..apdu_len]).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // Response is MACt(8) only - no encrypted RespData (§10.7.1).
    channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array};
    use crate::types::KeyNumber;
    use crate::types::file_settings::*;
    use alloc::vec::Vec;

    fn authenticated_aes(
        enc_key: [u8; 16],
        mac_key: [u8; 16],
        ti: [u8; 4],
        cmd_counter: u16,
    ) -> Authenticated<AesSuite> {
        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        for _ in 0..cmd_counter {
            state.advance_counter();
        }
        state
    }

    /// Build a synthetic ChangeFileSettings APDU pair.
    ///
    /// Produces `(C-APDU, R-APDU body)` by running the AES suite
    /// directly. Used for tests that don't have published vectors.
    fn synthesise_change_fs_apdu(
        enc_key: [u8; 16],
        mac_key: [u8; 16],
        ti: [u8; 4],
        cmd_ctr: u16,
        file_no: u8,
        settings: &FileSettingsUpdate,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut suite = AesSuite::from_keys(enc_key, mac_key);

        let mut raw = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let raw_len = settings.encode(&mut raw).unwrap();

        let padded_len = (raw_len + 1).div_ceil(BLOCK) * BLOCK;
        let mut padded = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN + BLOCK];
        padded[..raw_len].copy_from_slice(&raw[..raw_len]);
        padded[raw_len] = 0x80;

        let ct = &mut padded[..padded_len];
        suite.encrypt(Direction::Command, &ti, cmd_ctr, ct);

        let mut mac_input = Vec::with_capacity(1 + 2 + 4 + 1 + ct.len());
        mac_input.push(CMD);
        mac_input.extend_from_slice(&cmd_ctr.to_le_bytes());
        mac_input.extend_from_slice(&ti);
        mac_input.push(file_no);
        mac_input.extend_from_slice(ct);
        let mac = suite.mac(&mac_input);

        let mut apdu = Vec::with_capacity(5 + 1 + ct.len() + MAC_LEN + 1);
        let lc = (1 + ct.len() + MAC_LEN) as u8;
        apdu.extend_from_slice(&[0x90, CMD, 0x00, 0x00, lc, file_no]);
        apdu.extend_from_slice(ct);
        apdu.extend_from_slice(&mac);
        apdu.push(0x00);

        // Response MAC over RC=00 || (CmdCtr+1) LE || TI.
        let resp_suite = AesSuite::from_keys([0u8; 16], mac_key);
        let next_ctr = cmd_ctr.wrapping_add(1);
        let mut resp_mac_input = Vec::with_capacity(7);
        resp_mac_input.push(0x00);
        resp_mac_input.extend_from_slice(&next_ctr.to_le_bytes());
        resp_mac_input.extend_from_slice(&ti);
        let resp_mac = resp_suite.mac(&resp_mac_input);

        (apdu, resp_mac.to_vec())
    }

    /// Round-trip a synthetic `ChangeFileSettings` for the NDEF file
    /// with SDM settings matching AN12196 §5.9 Table 18.
    #[test]
    fn change_file_settings_full_roundtrip() {
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let ti = hex_array("D779B1D0");

        let sdm = Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key2,
                offset: Offset::new(0x20).unwrap(),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Key(KeyNumber::Key1),
                }),
            },
            Some(FileRead::MacOnly {
                key: KeyNumber::Key1,
                window: MacWindow {
                    input: Offset::new(0x43).unwrap(),
                    mac: Offset::new(0x43).unwrap(),
                },
            }),
            None,
            CryptoMode::Aes,
        )
        .expect("valid SDM settings");

        let settings = FileSettingsUpdate::new(
            CommMode::Plain,
            AccessRights {
                read: Access::Free,
                write: Access::Key(KeyNumber::Key0),
                read_write: Access::Key(KeyNumber::Key0),
                change: Access::Key(KeyNumber::Key0),
            },
        )
        .with_sdm(sdm);

        let (expected_apdu, resp_body) =
            synthesise_change_fs_apdu(enc_key, mac_key, ti, 0, 0x02, &settings);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_file_settings(&mut transport, &mut ch, 0x02, &settings).await
        })
        .expect("ChangeFileSettings must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// PICC error (`PERMISSION_DENIED` = `91 9D`) surfaces correctly.
    #[test]
    fn change_file_settings_permission_denied() {
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let ti = hex_array("D779B1D0");

        let settings = FileSettingsUpdate::new(
            CommMode::Plain,
            AccessRights {
                read: Access::Free,
                write: Access::Free,
                read_write: Access::Free,
                change: Access::Free,
            },
        );

        let (expected_apdu, _) =
            synthesise_change_fs_apdu(enc_key, mac_key, ti, 0, 0x02, &settings);

        let mut transport = TestTransport::new([Exchange::new(&expected_apdu, &[], 0x91, 0x9D)]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_file_settings(&mut transport, &mut ch, 0x02, &settings).await
        });

        match result {
            Err(SessionError::ErrorResponse(ResponseStatus::PermissionDenied)) => (),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
        // Counter must not advance on error.
        assert_eq!(state.counter(), 0);
    }

    /// Minimal settings (no SDM) produce a short payload that still pads
    /// to one 16-byte block.
    #[test]
    fn change_file_settings_no_sdm_roundtrip() {
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let ti = hex_array("D779B1D0");

        let settings = FileSettingsUpdate::new(
            CommMode::Full,
            AccessRights {
                read: Access::Key(KeyNumber::Key2),
                write: Access::Key(KeyNumber::Key3),
                read_write: Access::Key(KeyNumber::Key3),
                change: Access::Key(KeyNumber::Key0),
            },
        );

        let (expected_apdu, resp_body) =
            synthesise_change_fs_apdu(enc_key, mac_key, ti, 3, 0x03, &settings);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 3);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_file_settings(&mut transport, &mut ch, 0x03, &settings).await
        })
        .expect("ChangeFileSettings (no SDM) must succeed");

        assert_eq!(state.counter(), 4);
        assert_eq!(transport.remaining(), 0);
    }
    /// Cross-implementation parity: byte-exact ChangeFileSettings (FS_RESET)
    /// APDU against the bolt-card-programmer web app.
    ///
    /// Vector from `bolt-card-programmer/refchangekey.js` (FS_RESET line,
    /// CmdCtr=3): the wipe-time NDEF file-settings reset — Plain comm,
    /// rights 0xEEE0 (R/W/RW free, change Key0), SDM disabled. Same
    /// synthetic session state as the ChangeKey parity tests (lesson B8).
    #[test]
    fn change_file_settings_bolt_card_programmer_parity_fs_reset() {
        use crate::testing::hex_bytes;

        let enc = hex_array("1234567890abcdef1234567890abcdef");
        let mac = hex_array("fedcba0987654321fedcba0987654321");
        let ti = hex_array("AABBCCDD");

        let update = FileSettingsUpdate::new(
            CommMode::Plain,
            AccessRights {
                read: Access::Free,
                write: Access::Free,
                read_write: Access::Free,
                change: Access::Key(KeyNumber::Key0),
            },
        )
        .with_sdm(Sdm::disabled());

        // refchangekey.js FS_RESET: 90 5F 00 00 19 02 E(CmdData 16) MACt(8) 00
        let expected = hex_bytes("905F00001902103f2395a25873b0635d930ad5776da7c96f2e0188d9fc9b00");

        // Response is MACt(8) only (§10.7.1): rc=0x00, next CmdCtr, TI, empty data.
        let next = 4u16;
        let mact_input = [
            0x00u8,
            next as u8,
            (next >> 8) as u8,
            ti[0],
            ti[1],
            ti[2],
            ti[3],
        ];
        let mact = AesSuite::from_keys([0u8; 16], mac).mac(&mact_input);

        let mut transport = TestTransport::new([Exchange::new(&expected, &mact, 0x91, 0x00)]);
        let mut state = Authenticated::new(AesSuite::from_keys(enc, mac), ti, KeyNumber::Key0);
        for _ in 0..3 {
            state.advance_counter();
        }

        block_on(async {
            let mut ch = crate::commands::SecureChannel::new(&mut state);
            change_file_settings(&mut transport, &mut ch, 0x02, &update).await
        })
        .expect("FS_RESET must match bolt-card-programmer byte-for-byte");
    }
}
