// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use core::error::Error;

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, Version},
};

/// Read version information in plain mode.
///
/// This uses `GetVersion` (INS `60`, NT4H2421Gx §10.5.2/§10.7) in
/// `CommMode.Plain`, before any authentication is in place.
///
/// Three chained frames: `90 60 00 00 00`, then twice `90 AF 00 00 00`.
/// Parts 1 and 2 are 7 bytes each (HW / SW info); Part 3 carries 14
/// bytes of production data (UID + batch + week + year).
pub(crate) async fn get_version<T: Transport>(
    transport: &mut T,
) -> Result<Version, SessionError<T::Error>> {
    let (part1, part2, last) = drive_chain(transport, &[0x90, 0x60, 0x00, 0x00, 0x00]).await?;
    let part3 = extract_part3(last.as_ref())?;
    Ok(Version {
        part1,
        part2,
        part3,
    })
}

/// `GetVersion` inside an authenticated session - `CommMode.MAC`
/// (NT4H2421Gx §10.2 Table 21).
///
/// Wire: `90 60 00 00 08 <MACt(8)> 00`, three chained frames.
/// The response `MACt` on the last frame covers all three response parts.
pub(crate) async fn get_version_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<Version, SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0x60, &[], &[]);
    let mut head = [0u8; 5 + 8 + 1];
    head[..5].copy_from_slice(&[0x90, 0x60, 0x00, 0x00, 0x08]);
    head[5..13].copy_from_slice(&cmd_mac);
    // head[13] = 0x00 (Le)

    let (part1, part2, last) = drive_chain(transport, &head).await?;
    let last = last.as_ref();
    if last.len() != 14 + 8 {
        return Err(SessionError::UnexpectedLength {
            got: last.len(),
            expected: 22,
        });
    }
    // RespData_all (part1 || part2 || part3_data) followed by MACt.
    let mut body = [0u8; 7 + 7 + 14 + 8];
    body[0..7].copy_from_slice(&part1);
    body[7..14].copy_from_slice(&part2);
    body[14..14 + last.len()].copy_from_slice(last);
    let verified = channel.verify_response_mac_and_advance(0x00, &body)?;
    let part3: [u8; 14] =
        verified[14..28]
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: verified.len(),
                expected: 28,
            })?;
    Ok(Version {
        part1,
        part2,
        part3,
    })
}

/// Drive the three-frame GetVersion chain and return `(part1, part2, part3_full)`.
/// `head` is the first APDU - `90 60 00 00 08 <MACt(8)> 00` for `CommMode.MAC`
/// (authenticated) or plain `90 60 00 00 00` for `CommMode.Plain`. Follow-on
/// frames are always the plain `91 AF` continuation; the caller decodes any
/// trailing `MACt` on the third response.
async fn drive_chain<T: Transport>(
    transport: &mut T,
    head: &[u8],
) -> Result<([u8; 7], [u8; 7], T::Data), SessionError<T::Error>> {
    let part1 = request_intermediate_part(transport, head).await?;
    let part2 = request_intermediate_part(transport, &[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;

    let r3 = transport.transmit(&[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;
    let code = ResponseCode::desfire(r3.sw1, r3.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok((part1, part2, r3.data))
}

/// Read one intermediate `GetVersion` frame.
///
/// Requires `91 AF` ("additional frame") and coerces the 7-byte payload
/// to `[u8; 7]`.
async fn request_intermediate_part<T: Transport>(
    transport: &mut T,
    apdu: &[u8],
) -> Result<[u8; 7], SessionError<T::Error>> {
    let resp = transport.transmit(apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    resp.data
        .as_ref()
        .try_into()
        .map_err(|_| SessionError::UnexpectedLength {
            got: resp.data.as_ref().len(),
            expected: 7,
        })
}

fn extract_part3<E: Error + core::fmt::Debug>(data: &[u8]) -> Result<[u8; 14], SessionError<E>> {
    data.get(..14)
        .ok_or(SessionError::UnexpectedLength {
            got: data.len(),
            expected: 14,
        })?
        .try_into()
        .map_err(|_| SessionError::UnexpectedLength {
            got: data.len(),
            expected: 14,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, LrpSuite, aes_cbc_decrypt};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use alloc::vec::Vec;

    /// Build the GetVersion head APDU with command MAC at the given counter.
    fn head_apdu(suite: &AesSuite, ti: [u8; 4], ctr: u16) -> Vec<u8> {
        let mut mac_input = Vec::new();
        mac_input.push(0x60u8); // INS
        mac_input.extend_from_slice(&ctr.to_le_bytes());
        mac_input.extend_from_slice(&ti);
        let cmd_mac = suite.mac(&mac_input);
        let mut apdu = Vec::from([0x90u8, 0x60, 0x00, 0x00, 0x08]);
        apdu.extend_from_slice(&cmd_mac);
        apdu.push(0x00); // Le
        apdu
    }

    /// Replay a plain `GetVersion` round-trip.
    ///
    /// Uses bytes captured from a real NTAG 424 DNA tag. The three
    /// response parts contain hardware
    /// and software version info (parts 1–2, 7 B each) and production data
    /// (part 3, 14 B including the 7-byte UID). No trailing MAC is present.
    ///
    /// APDUs and responses validated on real NTAG 424 DNA hardware - both AES
    /// and LRP tags return identical part1/part2; part3 varies only in the UID.
    #[test]
    fn get_version_plain_roundtrip() {
        let part1 = [0x04u8, 0x04, 0x08, 0x30, 0x00, 0x11, 0x05];
        let part2 = [0x04u8, 0x04, 0x02, 0x01, 0x02, 0x11, 0x05];
        let part3 = hex_array::<14>("04984C7A0B1090CF5D9045104621");

        let mut transport = TestTransport::new([
            Exchange::new(&[0x90, 0x60, 0x00, 0x00, 0x00], &part1, 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part2, 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part3, 0x91, 0x00),
        ]);

        let version = block_on(get_version(&mut transport)).expect("plain GetVersion must succeed");

        assert_eq!(version.part1, part1);
        assert_eq!(version.part2, part2);
        assert_eq!(version.part3, part3);
        assert_eq!(*version.uid(), [0x04, 0x98, 0x4C, 0x7A, 0x0B, 0x10, 0x90]);
        assert_eq!(transport.remaining(), 0);
    }

    /// Authenticated `GetVersion` round-trip. Session keys are from AN12196 §5.6
    /// (key 0x00 handshake - a published vector); response parts are from AN12196
    /// §5.5. The response MAC is derived by the test so its correctness is only as
    /// good as the MAC implementation - but the wire format (8-byte command MAC
    /// in Lc, 8-byte response `MACt` on the last frame) is confirmed on hardware:
    /// a real PICC accepts the command and returns a valid `MACt`.
    #[test]
    fn get_version_mac_roundtrip() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let part1 = hex_bytes("0404083000110591AF"); // AN12196 §5.5 step 5
        let part2 = hex_bytes("0404020101110591AF"); // step 7
        let part3_data = hex_bytes("04968CAA5C5E80CD65935D402118"); // step 9 (14 B)
        assert_eq!(part3_data.len(), 14);

        let suite = AesSuite::from_keys(enc_key, mac_key);
        let head = head_apdu(&suite, ti, 0);

        // Derive the expected MACt over concatenated response data at CmdCtr+1=1.
        let mut mac_input = Vec::new();
        mac_input.push(0x00); // RC for 91 00
        mac_input.extend_from_slice(&1u16.to_le_bytes()); // CmdCtr after advance
        mac_input.extend_from_slice(&ti);
        mac_input.extend_from_slice(&part1[..7]);
        mac_input.extend_from_slice(&part2[..7]);
        mac_input.extend_from_slice(&part3_data);
        let expected_mac = suite.mac(&mac_input);

        let mut part3_full = part3_data.clone();
        part3_full.extend_from_slice(&expected_mac);

        let mut transport = TestTransport::new([
            Exchange::new(&head, &part1[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part2[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part3_full, 0x91, 0x00),
        ]);

        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        let version = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        })
        .expect("authenticated GetVersion must succeed");

        assert_eq!(version.part1, part1[..7]);
        assert_eq!(version.part2, part2[..7]);
        assert_eq!(version.part3.as_slice(), part3_data.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Tampering with the trailing `MACt` on the last frame surfaces as
    /// [`SessionError::ResponseMacMismatch`]. `CmdCtr` must not advance on
    /// failure - the caller can retry or abort, and a stale counter would
    /// de-sync the session.
    #[test]
    fn get_version_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let part1 = hex_bytes("0404083000110591AF");
        let part2 = hex_bytes("0404020101110591AF");
        let part3_data = hex_bytes("04968CAA5C5E80CD65935D402118");

        let suite = AesSuite::from_keys(enc_key, mac_key);
        let mut mac_input = Vec::new();
        mac_input.push(0x00);
        mac_input.extend_from_slice(&1u16.to_le_bytes());
        mac_input.extend_from_slice(&ti);
        mac_input.extend_from_slice(&part1[..7]);
        mac_input.extend_from_slice(&part2[..7]);
        mac_input.extend_from_slice(&part3_data);
        let mut bad_mac = suite.mac(&mac_input);
        bad_mac[0] ^= 0x01;

        let mut part3_full = part3_data.clone();
        part3_full.extend_from_slice(&bad_mac);

        let head = head_apdu(&suite, ti, 0);
        let mut transport = TestTransport::new([
            Exchange::new(&head, &part1[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part2[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part3_full, 0x91, 0x00),
        ]);

        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    fn aes_key0_suite_085bc941() -> (AesSuite, [u8; 4]) {
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("C4028B41E6F497099C7087768E78A191");
        let mut rnd_b = hex_array::<16>("7858A0B9DBC468F0FF1B2F773D6DF9FC");
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();
        (
            AesSuite::derive(&key, &rnd_a, &rnd_b),
            hex_array("085BC941"),
        )
    }

    fn lrp_key0_suite_bbe12900() -> (LrpSuite, [u8; 4]) {
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("0272F1390C4B8EC7D3E43308D4B41EC3");
        // LRP Part1 response = 01 || RndB; RndB is plaintext (no decrypt needed).
        let rnd_b = hex_array::<16>("57E5BF7AF415C4C8B330442EC1F265E9");
        // enc_ctr=1: AuthenticateLRPFirst decrypts one block during the handshake.
        (
            LrpSuite::derive(&key, &rnd_a, &rnd_b).with_enc_ctr(1),
            hex_array("BBE12900"),
        )
    }

    /// Replay a hardware-captured `GetVersion` in MAC mode (AES session).
    ///
    /// From the AES hw capture (TI=085BC941): CmdCtr = 0 at call time
    /// (first command after Key0 authentication). UID = 04A9707A0B1090.
    #[test]
    fn get_version_mac_hw_aes() {
        let (suite, ti) = aes_key0_suite_085bc941();
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);

        let mut transport = TestTransport::new([
            Exchange::new(
                &hex_bytes("90600000087EB6309891B11B2400"),
                &hex_bytes("04040830001105"),
                0x91,
                0xAF,
            ),
            Exchange::new(
                &hex_bytes("90AF000000"),
                &hex_bytes("04040201021105"),
                0x91,
                0xAF,
            ),
            Exchange::new(
                &hex_bytes("90AF000000"),
                &hex_bytes("04A9707A0B1090CF5D9045104621EB9482FFE8BB7761"),
                0x91,
                0x00,
            ),
        ]);

        let version = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        })
        .expect("hw AES GetVersion must succeed");

        assert_eq!(*version.uid(), [0x04, 0xA9, 0x70, 0x7A, 0x0B, 0x10, 0x90]);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured `GetVersion` in MAC mode (LRP session).
    ///
    /// From the LRP hw capture (TI=BBE12900): CmdCtr = 0 at call time
    /// (first command after Key0 authentication). UID = 04407A7A0B1090.
    #[test]
    fn get_version_mac_hw_lrp() {
        let (suite, ti) = lrp_key0_suite_bbe12900();
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);

        let mut transport = TestTransport::new([
            Exchange::new(
                &hex_bytes("906000000855C76087DF2A8F9000"),
                &hex_bytes("04040830001105"),
                0x91,
                0xAF,
            ),
            Exchange::new(
                &hex_bytes("90AF000000"),
                &hex_bytes("04040201021105"),
                0x91,
                0xAF,
            ),
            Exchange::new(
                &hex_bytes("90AF000000"),
                &hex_bytes("04407A7A0B1090CF5D90451046210C084938BB57C2CA"),
                0x91,
                0x00,
            ),
        ]);

        let version = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        })
        .expect("hw LRP GetVersion must succeed");

        assert_eq!(*version.uid(), [0x04, 0x40, 0x7A, 0x7A, 0x0B, 0x10, 0x90]);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }
}
