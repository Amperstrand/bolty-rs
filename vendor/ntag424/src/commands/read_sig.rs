// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, SIGNATURE_LEN},
};

/// `Read_Sig` (INS `3C`, NT4H2421Gx §10.12) in `CommMode.Plain`.
///
/// Wire: `CLA=90 INS=3C P1=00 P2=00 Lc=01 Data=00 Le=00`. Returns the
/// 56-byte ECDSA originality signature (`r ‖ s`, 28 bytes each,
/// big-endian).
///
/// Unauthenticated PICCs sometimes answer with `91 90` (a "documented
/// by example" status in AN12196 Table 30) instead of `91 00`; both
/// are accepted here.
pub(crate) async fn read_sig<T: Transport>(
    transport: &mut T,
) -> Result<[u8; SIGNATURE_LEN], SessionError<T::Error>> {
    let resp = transport
        .transmit(&[0x90, 0x3C, 0x00, 0x00, 0x01, 0x00, 0x00])
        .await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(
        code.status(),
        ResponseStatus::Unknown(0x9190) | ResponseStatus::OperationOk
    ) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let data = resp.data.as_ref();
    data.try_into().map_err(|_| SessionError::UnexpectedLength {
        got: data.len(),
        expected: SIGNATURE_LEN,
    })
}

/// Ciphertext length for an authenticated `Read_Sig` response.
///
/// A 56-byte signature padded with ISO/IEC 9797-1 Method 2 reaches the
/// next 16-byte AES-CBC boundary at 64 bytes.
const READ_SIG_CT_LEN: usize = 64;

/// `Read_Sig` inside an authenticated session - `CommMode.FULL` (§9.1.4).
///
/// Wire: `90 3C 00 00 09 00 <MACt(8)> 00`, response
/// `<AES-CBC(sig || 80 00..00)(64 B)> <MACt(8)>` with SW `91 00` or
/// `91 90`. Although Table 21 in older revisions of the spec places
/// `Read_Sig` in MAC mode, real PICCs return a 64-byte encrypted
/// payload - i.e. Full mode - so the signature arrives ciphered with
/// the response IV derived from `(TI, CmdCtr+1)`. The PICC also
/// answers with `91 90` (the AN12196 §7 Table 30 "by example" status)
/// rather than `91 00` in both Plain and MAC frames, so both are
/// accepted here. `CmdCtr` advances on success.
pub(crate) async fn read_sig_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<[u8; SIGNATURE_LEN], SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0x3C, &[0x00], &[]);
    let mut apdu = [0u8; 5 + 1 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0x3C, 0x00, 0x00, 0x09]);
    apdu[5] = 0x00; // CmdHeader: signature number
    apdu[6..14].copy_from_slice(&cmd_mac);
    // apdu[14] = 0x00 (Le)

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(
        code.status(),
        ResponseStatus::OperationOk | ResponseStatus::Unknown(0x9190)
    ) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // 64 B ciphertext = sig (56 B) || ISO/IEC 9797-1 M2 pad to 64 B.
    channel.decrypt_full_fixed::<READ_SIG_CT_LEN, SIGNATURE_LEN, T::Error>(
        resp.sw2,
        resp.data.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{
        Exchange, TestTransport, aes_key0_suite_085bc941, block_on, hex_array, hex_bytes,
        lrp_key0_suite_bbe12900,
    };
    use alloc::vec::Vec;

    /// Build an authenticated `Read_Sig` ciphertext.
    ///
    /// This is the 64-byte `CommMode.FULL` ciphertext the PICC would
    /// send: `sig || 80 || 00..00` encrypted under the response IV for
    /// `CmdCtr+1`.
    fn encrypt_sig(suite_keys: (&[u8; 16], &[u8; 16]), ti: [u8; 4], sig: &[u8]) -> [u8; 64] {
        let (enc_key, mac_key) = suite_keys;
        let mut buf = [0u8; 64];
        buf[..sig.len()].copy_from_slice(sig);
        buf[sig.len()] = 0x80;
        // remaining bytes stay zero
        let mut suite = AesSuite::from_keys(*enc_key, *mac_key);
        suite.encrypt(Direction::Response, &ti, 1, &mut buf);
        buf
    }

    /// Authenticated `Read_Sig` round-trip. Uses the AN12196 §5.6 key 0
    /// session material and a plausible 56-byte signature; both the
    /// request command-MAC and the encrypted response payload + MAC are
    /// derived here from the very same `AesSuite` implementation - the
    /// spec gives no worked authenticated `Read_Sig` example. Pinning
    /// `CommMode.FULL` framing (encrypted sig with ISO 9797-1 Method 2
    /// padding, then MAC over the ciphertext).
    #[test]
    fn read_sig_mac_roundtrip() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        // The signature bytes are opaque to this test - any 56 distinct
        // bytes work; ECDSA verification is exercised elsewhere.
        let sig: Vec<u8> = (0..56u8).collect();
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x3C);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(0x00);
            suite.mac(&input)
        };

        let ciphertext = encrypt_sig((&enc_key, &mac_key), ti, &sig);

        // Response MAC over RC=00 || CmdCtr+1=1 || TI || ciphertext.
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0x3C, 0x00, 0x00, 0x09, 0x00]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(
            AesSuite::from_keys(enc_key, mac_key),
            ti,
            crate::KeyNumber::Key0,
        );
        let out = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_sig_mac(&mut transport, &mut ch).await
        })
        .expect("authenticated Read_Sig must succeed");

        assert_eq!(out.as_slice(), sig.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Reject a bad `Read_Sig` response MAC.
    ///
    /// A bad trailing MAC surfaces as `ResponseMacMismatch` and keeps
    /// `CmdCtr` pinned; decryption is never attempted.
    #[test]
    fn read_sig_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let sig: Vec<u8> = (0..56u8).collect();
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x3C);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(0x00);
            suite.mac(&input)
        };

        let ciphertext = encrypt_sig((&enc_key, &mac_key), ti, &sig);

        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0x3C, 0x00, 0x00, 0x09, 0x00]);
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
            read_sig_mac(&mut transport, &mut ch).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// Replay a hardware-captured `ReadSig` in plain mode (AES tag).
    ///
    /// No session state required - CommMode.Plain returns the 56-byte ECC
    /// signature directly. SW2 = 0x90 is an NTAG-specific status code for
    /// this command. UID = 04A9707A0B1090.
    #[test]
    fn read_sig_plain_hw_aes() {
        let sig = hex_bytes(
            "03F0A17889E3063D2D01CD8750734601BC031C26812705A1BD3B75361604B19B762DC285DCE303A5B6DE5F2814F0449BA64AB445A7AEC4CF",
        );
        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("903C0000010000"),
            &sig,
            0x91,
            0x90,
        )]);

        let got = block_on(read_sig(&mut transport)).expect("hw plain Read_Sig must succeed");

        assert_eq!(got.len(), 56);
        assert_eq!(got.as_slice(), sig.as_slice());
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured `ReadSig` in plain mode (LRP tag).
    ///
    /// Plain mode, SW2 = 0x90. UID = 04407A7A0B1090.
    #[test]
    fn read_sig_plain_hw_lrp() {
        let sig = hex_bytes(
            "5F019173DA747943318455D4DD9413858C8D335D4B488DC52A606386115C5C796CE79E95A499C430B6DD5D1CD41BF23F258C678070DBD42C",
        );
        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("903C0000010000"),
            &sig,
            0x91,
            0x90,
        )]);

        let got = block_on(read_sig(&mut transport)).expect("hw plain Read_Sig must succeed");

        assert_eq!(got.len(), 56);
        assert_eq!(got.as_slice(), sig.as_slice());
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured authenticated `ReadSig` (AES session).
    ///
    /// TI=085BC941, CmdCtr = 1 at call time (after GetVersion). SW2 = 0x90
    /// (NTAG-specific status for this command).
    #[test]
    fn read_sig_mac_hw_aes() {
        let (suite, ti) = aes_key0_suite_085bc941();
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);
        state.advance_counter(); // 0→1 (GetVersion)

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("903C0000090032E6A647B984427F00"),
            &hex_bytes(
                "C2907EA2100DA5336DDDF17EE7AD70A240915DCD38E6319A663445D69E14825AF42F6AC725487F163ECC696B504F90390DF67BC5D8C0DBFCE2158FFB5A2A427AE1E8BDA4D293F528",
            ),
            0x91,
            0x90,
        )]);

        let sig = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_sig_mac(&mut transport, &mut ch).await
        })
        .expect("hw AES Read_Sig must succeed");

        assert_eq!(sig.len(), 56);
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured authenticated `ReadSig` (LRP session).
    ///
    /// TI=BBE12900, CmdCtr = 1 at call time (after GetVersion). SW2 = 0x90
    /// (NTAG-specific status for this command).
    #[test]
    fn read_sig_mac_hw_lrp() {
        let (suite, ti) = lrp_key0_suite_bbe12900();
        let mut state = Authenticated::new(suite, ti, crate::KeyNumber::Key0);
        state.advance_counter(); // 0→1 (GetVersion)

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("903C000009000C525883EFF7777400"),
            &hex_bytes(
                "E6DD25572D69A8D89C705AAC541BAD3D6DC5E50FCC8BE583E6487A07AB283F0A8CFD0A5097ACE24DB86C80C6D41A93C3FE1F1144D8E5D1873E1D50F10362E3F63766345847D34250",
            ),
            0x91,
            0x90,
        )]);

        let sig = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_sig_mac(&mut transport, &mut ch).await
        })
        .expect("hw LRP Read_Sig must succeed");

        assert_eq!(sig.len(), 56);
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }
}
