// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `ChangeKey` command - NT4H2421Gx §10.6.1, AN12196 §5.16.

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{KeyNumber, NonMasterKeyNumber, ResponseCode, ResponseStatus},
};

/// Compute the `CRC32NK` value.
///
/// This is CRC32/ISO-HDLC (IEEE Std 802.3-2008) as required by
/// NT4H2421Gx Table 63 footnote [1].
///
/// NXP convention (consistent with the AN12196 §5.16.1 vector): the
/// register is initialised to `0xFFFF_FFFF` but the final one's-complement
/// is **not** applied - the raw residue is written into the stream
/// little-endian (verified against Table 25 step 7: key
/// `F3847D62…` → `789DFADC`).
fn crc32(data: &[u8]) -> [u8; 4] {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc.to_le_bytes()
}

/// Change a non-master application key.
///
/// This is `ChangeKey` (INS `C4`) Case 1 (NT4H2421Gx §10.6.1,
/// AN12196 §5.16.1, Table 25).
///
/// Authentication with application key 0 is required before calling this.
///
/// Plaintext layout (32 bytes after ISO/IEC 9797-1 Method 2 padding):
/// `(NewKey ⊕ OldKey) || KeyVer || CRC32(NewKey) || 0x80 || 0x00*10`.
///
/// `old_key` must be the current PICC key for `key_no`. The PICC responds
/// with an 8-byte `MACt` which is verified before returning. `CmdCtr` is
/// advanced on success.
pub(crate) async fn change_key<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    key_no: NonMasterKeyNumber,
    new_key: &[u8; 16],
    new_key_version: u8,
    old_key: &[u8; 16],
) -> Result<(), SessionError<T::Error>> {
    let mut plaintext = [0u8; 32];
    for i in 0..16 {
        plaintext[i] = new_key[i] ^ old_key[i];
    }
    plaintext[16] = new_key_version;
    plaintext[17..21].copy_from_slice(&crc32(new_key));
    plaintext[21] = 0x80;

    transmit(transport, channel, KeyNumber::from(key_no), plaintext, true).await
}

/// Change the application master key.
///
/// This is `ChangeKey` (INS `C4`) Case 2 for `Key0`
/// (NT4H2421Gx §10.6.1, AN12196 §5.16.2, Table 26).
///
/// Authentication with key 0 is required before calling this. Plaintext
/// layout (32 bytes after padding): `NewKey || KeyVer || 0x80 || 0x00*14`.
/// The PICC responds with `91 00` only - there is no `MACt`. `CmdCtr` is
/// advanced on success but the session keys are no longer valid for any
/// further command and the caller must re-authenticate.
pub(crate) async fn change_master_key<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    new_key: &[u8; 16],
    new_key_version: u8,
) -> Result<(), SessionError<T::Error>> {
    let mut plaintext = [0u8; 32];
    plaintext[..16].copy_from_slice(new_key);
    plaintext[16] = new_key_version;
    plaintext[17] = 0x80;

    transmit(transport, channel, KeyNumber::Key0, plaintext, false).await
}

/// Send a prepared `ChangeKey` APDU.
///
/// Encrypts the prepared 32-byte plaintext, builds the `90 C4 …` APDU,
/// sends it, and either verifies the trailing `MACt` (Case 1) or checks
/// that the response body is empty (Case 2). Advances `CmdCtr` on
/// success.
async fn transmit<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    key_no: KeyNumber,
    mut plaintext: [u8; 32],
    expect_mact: bool,
) -> Result<(), SessionError<T::Error>> {
    channel.encrypt_command(&mut plaintext)?;

    // MAC: Cmd || CmdCtr(LE) || TI || KeyNo (header) || ciphertext (data).
    let key_no_byte = key_no.as_byte();
    let mac = channel.compute_cmd_mac(0xC4, &[key_no_byte], &plaintext);

    // APDU: 90 C4 00 00 29 KeyNo ciphertext(32) MACt(8) 00
    // Lc = 1 + 32 + 8 = 41 = 0x29.
    let mut apdu = [0u8; 5 + 1 + 32 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xC4, 0x00, 0x00, 0x29]);
    apdu[5] = key_no_byte;
    apdu[6..38].copy_from_slice(&plaintext);
    apdu[38..46].copy_from_slice(&mac);
    // apdu[46] = 0x00 (Le) - already zero.

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let body = resp.data.as_ref();
    if expect_mact {
        // Case 1: 8-byte MACt over empty RespData (§5.16.1 Table 25 step 20).
        channel.verify_response_mac_and_advance(resp.sw2, body)?;
    } else {
        // Case 2: PICC returns 91 00 with no MACt (§5.16.2 Table 26 step 18).
        if !body.is_empty() {
            return Err(SessionError::UnexpectedLength {
                got: body.len(),
                expected: 0,
            });
        }
        channel.advance_counter();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};

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

    /// Replay the AN12196 non-master `ChangeKey` vector.
    ///
    /// AN12196 §5.16.1, Table 25 changes key 2 while authenticated with
    /// key 0.
    ///
    /// All values are taken verbatim from the application note.
    #[test]
    fn change_key_case1_an12196_vector() {
        let mac_key = hex_array("5529860B2FC5FB6154B7F28361D30BF9");
        let enc_key = hex_array("4CF3CB41A22583A61E89B158D252FC53");
        let ti = hex_array("7614281A");

        // Step 3: old key for key 2 (all zeros).
        let old_key = [0u8; 16];
        // Step 4/5: new key and version.
        let new_key = hex_array("F3847D627727ED3BC9C4CC050489B966");
        let new_key_version: u8 = 0x01;

        // Step 19: expected C-APDU.
        let expected_apdu = hex_bytes(
            "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600",
        );
        // Step 20: R-APDU (8-byte MACt + 9100).
        let resp_body = hex_bytes("203BB55D1089D587");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        // CmdCtr starts at 2 (step 14: CmdCtr = 0200 LE).
        let mut state = authenticated_aes(enc_key, mac_key, ti, 2);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_key(
                &mut transport,
                &mut ch,
                NonMasterKeyNumber::Key2,
                &new_key,
                new_key_version,
                &old_key,
            )
            .await
        })
        .expect("ChangeKey Case 1 must succeed");

        assert_eq!(state.counter(), 3);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay the AN12196 master-key `ChangeKey` vector.
    ///
    /// AN12196 §5.16.2, Table 26 changes key 0 while authenticated with
    /// key 0. No `MACt` appears in the response.
    #[test]
    fn change_master_key_case2_an12196_vector() {
        let mac_key = hex_array("5529860B2FC5FB6154B7F28361D30BF9");
        let enc_key = hex_array("4CF3CB41A22583A61E89B158D252FC53");
        let ti = hex_array("7614281A");

        let new_key = hex_array("5004BF991F408672B1EF00F08F9E8647");
        let new_key_version: u8 = 0x01;

        // Step 17: expected C-APDU.
        let expected_apdu = hex_bytes(
            "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200",
        );

        let mut transport = TestTransport::new([Exchange::new(&expected_apdu, &[], 0x91, 0x00)]);

        // CmdCtr starts at 3 (step 9: CmdCtr = 0300 LE).
        let mut state = authenticated_aes(enc_key, mac_key, ti, 3);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_master_key(&mut transport, &mut ch, &new_key, new_key_version).await
        })
        .expect("ChangeKey Case 2 must succeed");

        assert_eq!(state.counter(), 4);
        assert_eq!(transport.remaining(), 0);
    }

    /// CRC32 sanity check against the AN12196 §5.16.1 vector (step 7).
    #[test]
    fn crc32_matches_an12196_case1_vector() {
        let new_key = hex_array::<16>("F3847D627727ED3BC9C4CC050489B966");
        // Step 7: CRC32(NewKey) = 789DFADC - these are the literal stream bytes.
        assert_eq!(crc32(&new_key), hex_array("789DFADC"));
    }
    /// Cross-implementation parity: byte-exact ChangeKey APDUs against the
    /// bolt-card-programmer web app (the reference card burner).
    ///
    /// Vectors generated by `bolt-card-programmer/refchangekey.js` with fixed
    /// synthetic session state and keys — the same vectors pin
    /// ccid-firmware-rs host-tools/boltwipe.py (method: bolty-rs lesson B8).
    /// Generator CmdCtr sequence: FS_RESET used 3, K1..K4 use 4..7, K0 uses 8.
    /// Semantics are wipe-to-factory: each vector replaces the on-card key
    /// with factory zeros (old = the per-slot key, new = 0x00*16, version 0).
    fn ref_state(enc: [u8; 16], mac: [u8; 16], ti: [u8; 4], ctr: u16) -> Authenticated<AesSuite> {
        let mut state = Authenticated::new(AesSuite::from_keys(enc, mac), ti, KeyNumber::Key0);
        for _ in 0..ctr {
            state.advance_counter();
        }
        state
    }

    fn ref_mact(mac: [u8; 16], ti: [u8; 4], ctr: u16) -> [u8; 8] {
        // verify_response_mac_and_advance with rc=0x00 and empty RespData.
        let next = ctr.wrapping_add(1);
        let input = [
            0x00u8,
            next as u8,
            (next >> 8) as u8,
            ti[0],
            ti[1],
            ti[2],
            ti[3],
        ];
        AesSuite::from_keys([0u8; 16], mac).mac(&input)
    }

    #[test]
    fn change_key_bolt_card_programmer_parity_k1_to_k4() {
        let enc = hex_array("1234567890abcdef1234567890abcdef");
        let mac = hex_array("fedcba0987654321fedcba0987654321");
        let ti = hex_array("AABBCCDD");
        let zeros = [0u8; 16];

        let vectors: [(NonMasterKeyNumber, u16, [u8; 16], &str); 4] = [
            (
                NonMasterKeyNumber::Key1,
                4,
                [0x11; 16],
                "90C400002901b7a4406e4b51e939dcf27c307fc2cf18432f62b7fb9e30003ef6daae5f6c4dc684d49060a28cdbdd00",
            ),
            (
                NonMasterKeyNumber::Key2,
                5,
                [0x22; 16],
                "90C400002902d1a53e1f93825b1e8d6d5e0a90c213847d52b2e9ee54e62bd5c290ee28d8c4f003c4d7617ba23cae00",
            ),
            (
                NonMasterKeyNumber::Key3,
                6,
                [0x33; 16],
                "90C400002903ab57d46bc81862236fa2234099363a7f58b208d761c25af1bf97c53e8c40d956f71e19b3e37d9ebc00",
            ),
            (
                NonMasterKeyNumber::Key4,
                7,
                [0x44; 16],
                "90C40000290434111e92114dd9730e82c726154cfda8a26a81d175678ac34ddf7685dcfb351902e71eef89540d7700",
            ),
        ];

        for (key_no, ctr, old_key, expected_hex) in vectors {
            let expected = hex_bytes(expected_hex);
            let mact = ref_mact(mac, ti, ctr);
            let mut transport = TestTransport::new([Exchange::new(&expected, &mact, 0x91, 0x00)]);
            let mut state = ref_state(enc, mac, ti, ctr);
            block_on(async {
                let mut ch = SecureChannel::new(&mut state);
                change_key(&mut transport, &mut ch, key_no, &zeros, 0x00, &old_key).await
            })
            .unwrap_or_else(|e| panic!("parity ChangeKey {key_no:?} ctr={ctr} failed: {e:?}"));
        }
    }

    #[test]
    fn change_master_key_bolt_card_programmer_parity_k0() {
        let enc = hex_array("1234567890abcdef1234567890abcdef");
        let mac = hex_array("fedcba0987654321fedcba0987654321");
        let ti = hex_array("AABBCCDD");
        let zeros = [0u8; 16];
        let expected = hex_bytes(
            "90C400002900a0479ccd9d633e088c1eb9ce19057e44937bb99f6bf5b890fb07ee23727d1054c778a2e4a2e17fbc00",
        );

        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x91, 0x00)]);
        let mut state = ref_state(enc, mac, ti, 8);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_master_key(&mut transport, &mut ch, &zeros, 0x00).await
        })
        .expect("parity ChangeMasterKey ctr=8 must match bolt-card-programmer");
    }
}
