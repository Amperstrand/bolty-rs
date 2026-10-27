// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `SetConfiguration` command - NT4H2421Gx §10.5.1, AN12196 §6, AN12321 §5.

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{Configuration, ResponseCode, ResponseStatus},
};

const CMD: u8 = 0x5C;

/// `SetConfiguration` (INS `5C`, NT4H2421Gx §10.5.1) in `CommMode.FULL`.
///
/// Authentication with the application master key (`Key0`) is required
/// before calling this. Each option set on `configuration` is sent as its
/// own APDU - `SetConfiguration` is single-option per command - in the
/// canonical order from Table 50: PICC, Secure Messaging, Capability,
/// Tag Tamper, Failed-Auth-Counter, HW. `CmdCtr` advances by one per option on
/// success.
///
/// All option payloads fit in a single 16-byte block after ISO/IEC 9797-1
/// Method 2 padding (the largest defined option, Capability, is 10 bytes),
/// so the encrypted-data field is always exactly 16 bytes.
///
/// Returns immediately without issuing any APDU when `configuration` carries
/// no options.
pub(crate) async fn set_configuration<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    configuration: &Configuration,
) -> Result<(), SessionError<T::Error>> {
    for (option_id, data) in configuration.build() {
        set_configuration_one(transport, channel, option_id, data).await?;
    }
    Ok(())
}

async fn set_configuration_one<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    option_id: u8,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    debug_assert!(
        !data.is_empty() && data.len() < 16,
        "SetConfiguration option data must be 1..=15 bytes (one block after pad)",
    );

    // ISO/IEC 9797-1 Method 2 padding to a single 16-byte block.
    let mut plaintext = [0u8; 16];
    plaintext[..data.len()].copy_from_slice(data);
    plaintext[data.len()] = 0x80;

    channel.encrypt_command(&mut plaintext)?;

    let mac = channel.compute_cmd_mac(CMD, &[option_id], &plaintext);

    // APDU: 90 5C 00 00 19 OptionID Ciphertext(16) MACt(8) 00.
    // Lc = 1 + 16 + 8 = 25 = 0x19.
    let mut apdu = [0u8; 5 + 1 + 16 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, CMD, 0x00, 0x00, 0x19]);
    apdu[5] = option_id;
    apdu[6..22].copy_from_slice(&plaintext);
    apdu[22..30].copy_from_slice(&mac);
    // apdu[30] = 0x00 (Le) - already zero.

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // NT4H2421Gx §10.5.1 Table 51 and hardware both show the PICC returning
    // just `9100` with no data bytes - no response MACt is appended.
    // AN12196 §6.2 Table 27 (Option 00h) shows an 8-byte MACt so we still
    // verify it when present; on real hardware Option 05h (and likely others)
    // returns an empty body (AN12321 §5 Table 3, confirmed on hardware).
    if resp.data.as_ref().is_empty() {
        channel.advance_counter();
    } else {
        channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
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

    /// Build a successful `SetConfiguration` response MAC.
    ///
    /// This is the 8-byte `MACt` the PICC would send for
    /// `RC=00 || (CmdCtr+1)(LE) || TI`, with no encrypted response data.
    fn response_mac(mac_key: [u8; 16], next_cmd_ctr: u16, ti: [u8; 4]) -> [u8; 8] {
        let suite = AesSuite::from_keys([0u8; 16], mac_key);
        let mut input = Vec::with_capacity(7);
        input.push(0x00);
        input.extend_from_slice(&next_cmd_ctr.to_le_bytes());
        input.extend_from_slice(&ti);
        suite.mac(&input)
    }

    /// AN12196 §6.2 Table 27 - `SetConfiguration` Option `00h` (PICC) enabling
    /// Random UID. Full round-trip including the response `MACt` from step 20.
    #[test]
    fn set_configuration_random_uid_an12196_vector() {
        // Steps 2–3 / 6.
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let ti = hex_array("D779B1D0");

        // Step 16 - full C-APDU.
        let expected_apdu =
            hex_bytes("905C000019008EA0138A7AF6FC8E99DF2A3A305602C43A7A3C9228C3134A00");
        // Step 17 - R-APDU body (8-byte MACt from step 21) + 9100.
        let resp_body = hex_bytes("86044208CAD1676A");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);
        let configuration = Configuration::new().with_random_uid_enabled();
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            set_configuration(&mut transport, &mut ch, &configuration).await
        })
        .expect("SetConfiguration RandomID must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// AN12321 §5 Table 3 - `SetConfiguration` Option `05h` (Capability) enabling
    /// LRP. The published table shows `9100` with no data bytes - confirmed on
    /// hardware. The C-APDU bytes are pinned against step 27.
    #[test]
    fn set_configuration_enable_lrp_an12321_vector() {
        // Steps 2–3 / 7.
        let mac_key = hex_array("7DE5F7E244A46D22E536804D07E8D70E");
        let enc_key = hex_array("66A8CB93269DC9BC2885B7A91B9C697B");
        let ti = hex_array("ED56F6E6");

        // Step 27 - full C-APDU.
        let expected_apdu =
            hex_bytes("905C0000190541B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300");
        // R-APDU: 9100 with no data bytes (AN12321 §5 Table 3, confirmed on hardware).

        let mut transport = TestTransport::new([Exchange::new(&expected_apdu, &[], 0x91, 0x00)]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);
        let configuration = Configuration::new().with_lrp_enabled();
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            set_configuration(&mut transport, &mut ch, &configuration).await
        })
        .expect("SetConfiguration enable-LRP must succeed");

        // Step 28 - CmdCtr advanced to 1.
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Skip I/O for an empty configuration.
    ///
    /// An empty `Configuration` must issue zero APDUs and leave
    /// `CmdCtr` untouched because the iterator over `build()` is empty.
    #[test]
    fn set_configuration_no_options_sends_nothing() {
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let ti = hex_array("D779B1D0");

        let mut transport = TestTransport::new([]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 7);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            set_configuration(&mut transport, &mut ch, &Configuration::new()).await
        })
        .expect("empty configuration must succeed without I/O");

        assert_eq!(state.counter(), 7);
        assert_eq!(transport.remaining(), 0);
    }

    /// Preserve Table 50 option order.
    ///
    /// A configuration touching two independent options must emit two
    /// APDUs in canonical order (PICC `00h` before Capability `05h`)
    /// and advance `CmdCtr` once per APDU.
    #[test]
    fn set_configuration_multi_option_advances_counter_in_order() {
        let mac_key = hex_array("FE4EDBF46536557E304682F33E63A84F");
        let enc_key = hex_array("7951A705F47F3C29B596454DC1490383");
        let ti = hex_array("D779B1D0");

        // First APDU: PICC (RandomID), CmdCtr = 0 - bit-identical to AN12196.
        let apdu_picc = hex_bytes("905C000019008EA0138A7AF6FC8E99DF2A3A305602C43A7A3C9228C3134A00");
        let resp_picc = hex_bytes("86044208CAD1676A");

        // Second APDU: Capability (LRP), CmdCtr = 1 - derive everything from
        // the same session keys so the test pins the iteration contract,
        // not arbitrary ciphertext bytes.
        let (apdu_cap, resp_cap) = synthesise_set_config_apdu(
            enc_key,
            mac_key,
            ti,
            1,
            0x05,
            &[0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0],
        );

        let mut transport = TestTransport::new([
            Exchange::new(&apdu_picc, &resp_picc, 0x91, 0x00),
            Exchange::new(&apdu_cap, &resp_cap, 0x91, 0x00),
        ]);

        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);
        let configuration = Configuration::new()
            .with_lrp_enabled()
            .with_random_uid_enabled();
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            set_configuration(&mut transport, &mut ch, &configuration).await
        })
        .expect("multi-option SetConfiguration must succeed");

        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// Build a synthetic `SetConfiguration` APDU pair.
    ///
    /// This helper builds a full `(C-APDU, R-APDU body)` pair for a
    /// given option using the AES suite directly. The multi-option test
    /// uses it to avoid hand-tabulating ciphertext and MAC bytes the
    /// application notes do not publish for these specific
    /// `(TI, CmdCtr)` combinations.
    fn synthesise_set_config_apdu(
        enc_key: [u8; 16],
        mac_key: [u8; 16],
        ti: [u8; 4],
        cmd_ctr: u16,
        option_id: u8,
        data: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        use crate::crypto::suite::Direction;

        let mut suite = AesSuite::from_keys(enc_key, mac_key);

        let mut plaintext = [0u8; 16];
        plaintext[..data.len()].copy_from_slice(data);
        plaintext[data.len()] = 0x80;
        suite.encrypt(Direction::Command, &ti, cmd_ctr, &mut plaintext);

        let mut mac_input = Vec::with_capacity(1 + 2 + 4 + 1 + 16);
        mac_input.push(0x5C);
        mac_input.extend_from_slice(&cmd_ctr.to_le_bytes());
        mac_input.extend_from_slice(&ti);
        mac_input.push(option_id);
        mac_input.extend_from_slice(&plaintext);
        let mac = suite.mac(&mac_input);

        let mut apdu = Vec::with_capacity(5 + 1 + 16 + 8 + 1);
        apdu.extend_from_slice(&[0x90, 0x5C, 0x00, 0x00, 0x19, option_id]);
        apdu.extend_from_slice(&plaintext);
        apdu.extend_from_slice(&mac);
        apdu.push(0x00);

        let resp_mac = response_mac(mac_key, cmd_ctr.wrapping_add(1), ti);
        (apdu, resp_mac.to_vec())
    }
}
