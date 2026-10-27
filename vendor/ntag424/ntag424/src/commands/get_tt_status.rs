// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, TagTamperStatusReadout},
};

/// `GetTTStatus` (INS `F7`, NT4H2421Tx §11.9.1) in `CommMode.FULL`.
///
/// Wire: `90 F7 00 00 08 <MACt(8)> 00`, response
/// `<E(TTPermStatus || TTCurrStatus || 80 00..00)(16 B)> <MACt(8)>` with SW
/// `91 00`. The command has no command-specific data parameters; the secure
/// messaging wrapper is the entire APDU body.
pub(crate) async fn get_tt_status<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<TagTamperStatusReadout, SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0xF7, &[], &[]);
    let mut apdu = [0u8; 5 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xF7, 0x00, 0x00, 0x08]);
    apdu[5..13].copy_from_slice(&cmd_mac);
    // apdu[13] = 0x00 (Le)

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let plain = channel.decrypt_full_fixed::<16, 2, T::Error>(resp.sw2, resp.data.as_ref())?;
    Ok(TagTamperStatusReadout::new(plain[0], plain[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{Direction, LrpSuite, SessionSuite};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use crate::types::TagTamperStatus;
    use alloc::vec::Vec;

    /// Reconstruct the post-auth LRP session from an `AuthenticateLRPFirst Key0`
    /// (all-zero master key) hardware capture.
    ///
    /// Derives the session suite from `(key=0, rnd_a, rnd_b)`, then decrypts
    /// `PICCData` to advance `EncCtr` 0→1 and extract `TI` (NT4H2421Tx
    /// §9.2.4, §9.2.5). Returns `(suite_with_enc_ctr_1, ti)`.
    fn lrp_key0_session(
        rnd_a: &[u8; 16],
        rnd_b: &[u8; 16],
        picc_data: &[u8; 16],
    ) -> (LrpSuite, [u8; 4]) {
        let key = [0u8; 16];
        let mut suite = LrpSuite::derive(&key, rnd_a, rnd_b);
        let mut plain = *picc_data;
        // Decrypt PICCData (EncCtr 0→1); plain = TI(4) || PDCap2(6) || PCDCap2(6).
        suite.decrypt(Direction::Response, &[0u8; 4], 0, &mut plain);
        let ti: [u8; 4] = plain[..4].try_into().expect("plain[..4] is always 4 bytes");
        (suite, ti)
    }

    /// Real hardware capture.
    ///
    /// `AuthenticateLRPFirst Key0` (all-zero) on a TT-capable tag with tamper
    /// enabled, followed by `GetTTStatus`. Session state at `GetTTStatus`:
    /// CmdCtr=0, EncCtr=1 (post-auth). Result: `permanent=Open, current=Open`.
    #[test]
    fn get_tt_status_hw_lrp_open() {
        let (suite, ti) = lrp_key0_session(
            &hex_array("E8185D2C4F7CFFD5196EA8F54FF648F3"),
            &hex_array("A2CC8C9721DFB09E3050DD5FA8A52549"),
            &hex_array("F9E461A3182B78D8FBFBFA6FA4C2DF93"),
        );
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);

        let expected_apdu = hex_bytes("90F7000008EA53D318617A367B00");
        let resp_body = hex_bytes("95B6CD54B7B7096940B330CDB927AD608C8A41613A7F3984");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let status = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        })
        .expect("hw GetTTStatus must succeed");

        assert_eq!(status.permanent(), TagTamperStatus::Open);
        assert_eq!(status.current(), TagTamperStatus::Open);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Real hardware capture.
    ///
    /// `AuthenticateLRPFirst Key0` (all-zero), `GetVersion` (CommMode.MAC,
    /// advances CmdCtr to 1, EncCtr unchanged), then `GetTTStatus` (tamper
    /// not yet enabled). Session state at `GetTTStatus`: CmdCtr=1, EncCtr=1.
    /// Result: `permanent=Invalid, current=Invalid`.
    #[test]
    fn get_tt_status_hw_lrp_invalid() {
        let (suite, ti) = lrp_key0_session(
            &hex_array("D96924CE20BDD49713436E07E96F7F0D"),
            &hex_array("06C285B7F8FCDEFF1FCE64E96158B3DE"),
            &hex_array("BDCE7A3114E5664D6411BF0B2E64C319"),
        );
        // GetVersion (CommMode.MAC, 3 frames) advanced CmdCtr to 1 without
        // touching EncCtr. Replay by advancing the counter directly.
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);
        state.advance_counter(); // CmdCtr 0→1 (GetVersion)

        let expected_apdu = hex_bytes("90F700000879A807E94C968F3300");
        let resp_body = hex_bytes("FD4225A32043321FFA19EB4AC0F2E2A4A9E6D6A89FB6D686");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let status = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        })
        .expect("hw GetTTStatus must succeed");

        assert_eq!(status.permanent(), TagTamperStatus::Invalid);
        assert_eq!(status.current(), TagTamperStatus::Invalid);
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// A corrupted response MAC is rejected without advancing `CmdCtr`.
    ///
    /// Uses the tt-open.txt hardware session (LRP Key0, CmdCtr=0, EncCtr=1):
    /// real command APDU, real response ciphertext, captured MAC with one bit
    /// flipped.
    #[test]
    fn get_tt_status_rejects_bad_trailer() {
        let (suite, ti) = lrp_key0_session(
            &hex_array("E8185D2C4F7CFFD5196EA8F54FF648F3"),
            &hex_array("A2CC8C9721DFB09E3050DD5FA8A52549"),
            &hex_array("F9E461A3182B78D8FBFBFA6FA4C2DF93"),
        );
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);

        let expected_apdu = hex_bytes("90F7000008EA53D318617A367B00");
        let ciphertext = hex_bytes("95B6CD54B7B7096940B330CDB927AD60");
        let mut bad_mac = hex_bytes("8C8A41613A7F3984");
        bad_mac[0] ^= 0x01;
        let mut resp_body = ciphertext;
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        });

        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// A ciphertext shorter than one block (16 bytes) is rejected after the
    /// MAC check passes. `CmdCtr` advances because the MAC was valid.
    ///
    /// Uses the tt-open.txt hardware session (LRP Key0, CmdCtr=0, EncCtr=1).
    #[test]
    fn get_tt_status_rejects_unexpected_ciphertext_length() {
        let (suite, ti) = lrp_key0_session(
            &hex_array("E8185D2C4F7CFFD5196EA8F54FF648F3"),
            &hex_array("A2CC8C9721DFB09E3050DD5FA8A52549"),
            &hex_array("F9E461A3182B78D8FBFBFA6FA4C2DF93"),
        );

        let short_ciphertext = [0xAAu8; 15];
        // Compute valid response MAC over the 15-byte body so the MAC check
        // passes; the subsequent length check then fires.
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00u8); // RC
            input.extend_from_slice(&1u16.to_le_bytes()); // CmdCtr+1 = 1 (LE)
            input.extend_from_slice(&ti);
            input.extend_from_slice(&short_ciphertext);
            suite.mac(&input)
        };
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);

        let expected_apdu = hex_bytes("90F7000008EA53D318617A367B00");
        let mut resp_body = Vec::from(short_ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        });

        match result {
            Err(SessionError::UnexpectedLength { got: 15, .. }) => (),
            other => panic!("expected UnexpectedLength {{ got: 15 }}, got {other:?}"),
        }
        assert_eq!(state.counter(), 1);
    }
}
