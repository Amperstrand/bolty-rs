// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus},
};

/// `GetCardUID` (INS `51`, NT4H2421Gx §10.5.3) in `CommMode.FULL`.
///
/// Wire: `90 51 00 00 08 <MACt(8)> 00`, response
/// `<E(UID || 80 00..00)(16 B)> <MACt(8)>` with SW `91 00`. The PICC
/// always returns the permanent 7-byte UID regardless of whether Random ID
/// mode is active (§10.5.3). `CmdCtr` advances on success.
pub(crate) async fn get_card_uid<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<[u8; 7], SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0x51, &[], &[]);
    let mut apdu = [0u8; 5 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0x51, 0x00, 0x00, 0x08]);
    apdu[5..13].copy_from_slice(&cmd_mac);
    // apdu[13] = 0x00 (Le)

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // 16 B ciphertext = UID (7 B) || ISO/IEC 9797-1 M2 pad to 16 B.
    channel.decrypt_full_fixed::<16, 7, T::Error>(resp.sw2, resp.data.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction, LrpSuite};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use alloc::vec::Vec;

    /// AN12196 §6.3 Table 28 - full `GetCardUID` round-trip.
    ///
    /// All values are taken verbatim from the application note (step numbers
    /// refer to Table 28). The test pins the full CommMode.FULL framing:
    /// command MAC, encrypted-UID response, response MAC, and UID recovery.
    #[test]
    fn get_card_uid_an12196_vector() {
        // Steps 2–5.
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];

        // Step 10: expected C-APDU (MACt from step 9).
        let expected_apdu = hex_bytes("90510000088E2C155ADDA99BE300");

        // Step 11: R-APDU body (ciphertext from step 15 + MACt from step 12).
        let resp_body = hex_bytes("70756055688505B52A5E26E59E329CD6595F672298EA41B7");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        let uid = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_card_uid(&mut transport, &mut ch).await
        })
        .expect("GetCardUID must succeed");

        // Step 19: permanent UID.
        assert_eq!(uid, [0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80]);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Build a `GetCardUID` response ciphertext.
    ///
    /// This is the 16-byte FULL-mode ciphertext the PICC would send for
    /// a given UID using the session ENC key.
    fn encrypt_uid(suite_keys: (&[u8; 16], &[u8; 16]), ti: [u8; 4], uid: &[u8; 7]) -> [u8; 16] {
        let (enc_key, mac_key) = suite_keys;
        let mut buf = [0u8; 16];
        buf[..7].copy_from_slice(uid);
        buf[7] = 0x80;
        // remaining bytes stay zero
        let mut suite = AesSuite::from_keys(*enc_key, *mac_key);
        suite.encrypt(Direction::Response, &ti, 1, &mut buf);
        buf
    }

    /// A bad trailing MAC surfaces as `ResponseMacMismatch` with `CmdCtr`
    /// left at zero.
    #[test]
    fn get_card_uid_rejects_bad_trailer() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let uid = [0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x51u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        let ciphertext = encrypt_uid((&enc_key, &mac_key), ti, &uid);

        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0x51, 0x00, 0x00, 0x08]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_card_uid(&mut transport, &mut ch).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// Replay a hardware-captured `GetCardUID` in Full mode (LRP session).
    ///
    /// TI=BBE12900, CmdCtr = 7 at call time (after GetVersion, ReadSig, and
    /// GetKeyVersion for Keys 0–4). UID = 04407A7A0B1090.
    #[test]
    fn get_card_uid_hw_lrp() {
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("0272F1390C4B8EC7D3E43308D4B41EC3");
        // LRP Part1 response = 01 || RndB; RndB is plaintext (no decrypt needed).
        let rnd_b = hex_array::<16>("57E5BF7AF415C4C8B330442EC1F265E9");
        let ti = hex_array::<4>("BBE12900");
        // enc_ctr=5: 1 block from AuthFirst + 4 blocks from ReadSig (64 B).
        // GetVersion and GetKeyVersion x5 are MAC-only (no encryption).
        let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b).with_enc_ctr(5);
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);
        for _ in 0..7 {
            state.advance_counter();
        }

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90510000087FE90A37B3B2DD3400"),
            &hex_bytes("C732E15E0F16F3137F0B21E67353F24C69CC9942061CF229"),
            0x91,
            0x00,
        )]);

        let uid = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_card_uid(&mut transport, &mut ch).await
        })
        .expect("hw LRP GetCardUID must succeed");

        assert_eq!(uid, [0x04, 0x40, 0x7A, 0x7A, 0x0B, 0x10, 0x90]);
        assert_eq!(state.counter(), 8);
        assert_eq!(transport.remaining(), 0);
    }
}
