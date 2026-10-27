// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `WriteData` command - NT4H2421Gx §10.8.2.
//!
//! The command writes bytes to a StandardData file. Its CommMode is
//! defined per file (§8.2.3.5, Table 13), so three framings are
//! exposed here:
//!
//! - [`write_data_plain`] - no secure messaging. Used either without
//!   an authenticated session at all, or, per §8.2.3.3, inside an
//!   authenticated session when the only satisfied access condition is
//!   the free-access one (`Eh`).
//! - [`write_data_mac`] - `CommMode.MAC` (§9.1.9): command gets an
//!   8-byte `MACt` trailer, response is `MACt(8)` only (no data).
//! - [`write_data_full`] - `CommMode.FULL` (§9.1.10): command data is
//!   encrypted with ISO/IEC 9797-1 Method 2 padding, MAC'd, and the
//!   response is `MACt(8)` only (no data).
//!
//! In all variants the command header is `FileNo(1) || Offset(3 LE) ||
//! Length(3 LE)`. Unlike `ReadData`, `Length = 0` is **not** valid
//! (Table 81: `000001h .. (FileSize - Offset)`).
//!
//! ## Chunking
//!
//! The PICC only supports short-form APDUs and has no application-layer
//! chaining for `WriteData` (§8.4 Table 16, §8.5), so writes whose
//! command body would exceed `Lc = 255` are split across multiple APDUs
//! at successive offsets by [`write_data_mac`] and [`write_data_full`].
//! Each per-APDU command carries its own `MACt` and advances `CmdCtr`.
//! The per-mode caps live on [`MAC_WRITE_CHUNK`] and [`FULL_WRITE_CHUNK`].
//!
//! The plain-mode chunk loop lives in the session layer instead (see
//! [`crate::session::Session::write_file_plain`]) because
//! [`write_data_plain`] is issued without a [`SecureChannel`] and the
//! `CmdCtr` increment is the caller's responsibility.

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus},
};

/// AES / LRP block size, used for FULL-mode padding arithmetic.
const BLOCK: usize = 16;

/// `MACt` trailer length (§9.1.3).
const MAC_LEN: usize = 8;

/// Max addressable file offset/length: 24-bit field per §10.8.2 Table 81.
const U24_MAX: u32 = 0x00FF_FFFF;

/// Maximum plaintext data bytes per single `WriteData` frame.
///
/// Table 81: "up to 248 byte including secure messaging". In `CommMode.Plain`
/// all 248 bytes carry user data. In MAC/FULL mode the 8-byte MACt and
/// potential cipher padding eat into this budget.
const WRITE_DATA_MAX_BODY: usize = 248;

/// Maximum short-APDU body length.
const MAX_APDU_BODY: usize = 255;

/// Max plaintext bytes per single `CommMode.MAC` `WriteData` APDU.
///
/// Body = `header(7) || data || MACt(8) ≤ 255` ⇒ data ≤ 240 bytes.
const MAC_WRITE_CHUNK: usize = 240;

/// Max plaintext bytes per single `CommMode.FULL` `WriteData` APDU.
///
/// Body = `header(7) || ciphertext || MACt(8) ≤ 255` ⇒ ciphertext ≤ 240
/// bytes (15 cipher blocks). M2 padding pushes plaintext of length `n`
/// to `(n+1).next_multiple_of(16)` bytes of ciphertext, so 239 → 240 ✓
/// but 240 → 256 ✗.
const FULL_WRITE_CHUNK: usize = 239;

fn validate_header<E: core::error::Error + core::fmt::Debug>(
    file_no: u8,
    offset: u32,
    length: usize,
) -> Result<(), SessionError<E>> {
    if file_no > 0x1F {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "file_no",
            value: file_no as usize,
            reason: "must fit 5 bits",
        });
    }
    if offset > U24_MAX {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "offset",
            value: offset as usize,
            reason: "must fit 24 bits",
        });
    }
    if length == 0 {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "data.len()",
            value: 0,
            reason: "must be non-zero",
        });
    }
    if length > U24_MAX as usize {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "data.len()",
            value: length,
            reason: "must fit the 24-bit Length field",
        });
    }
    Ok(())
}

fn validate_body_len<E: core::error::Error + core::fmt::Debug>(
    body_len: usize,
) -> Result<(), SessionError<E>> {
    if body_len > MAX_APDU_BODY {
        return Err(SessionError::ApduBodyTooLarge {
            got: body_len,
            max: MAX_APDU_BODY,
        });
    }
    Ok(())
}

/// Build the 7-byte command header `FileNo || Offset(3 LE) || Length(3 LE)`.
fn build_header(file_no: u8, offset: u32, length: u32) -> [u8; 7] {
    debug_assert!(file_no <= 0x1F);
    debug_assert!(offset <= U24_MAX);
    debug_assert!(length > 0 && length <= U24_MAX);
    let o = offset.to_le_bytes();
    let l = length.to_le_bytes();
    [file_no, o[0], o[1], o[2], l[0], l[1], l[2]]
}

/// `WriteData` (INS `8D`, §10.8.2) in `CommMode.Plain`.
///
/// Wire: `90 8D 00 00 <Lc> FileNo Offset(3 LE) Length(3 LE) Data 00`.
/// This helper only emits the plain APDU framing: it does not compute or
/// verify secure-messaging data itself. When called through an authenticated
/// session wrapper, that wrapper is responsible for advancing the tracked
/// command counter after a successful response.
///
pub(crate) async fn write_data_plain<T: Transport>(
    transport: &mut T,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    validate_header(file_no, offset, data.len())?;
    validate_body_len(7 + data.len())?;

    let header = build_header(file_no, offset, data.len() as u32);
    let lc = (7 + data.len()) as u8;
    let mut apdu = [0u8; 5 + 7 + WRITE_DATA_MAX_BODY + 1];
    apdu[..5].copy_from_slice(&[0x90, 0x8D, 0x00, 0x00, lc]);
    apdu[5..12].copy_from_slice(&header);
    apdu[12..12 + data.len()].copy_from_slice(data);
    let end = 12 + data.len();
    apdu[end] = 0x00; // Le

    let resp = transport.transmit(&apdu[..end + 1]).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok(())
}

/// `WriteData` in `CommMode.MAC` (§9.1.9).
///
/// Splits into multiple APDUs when the command body would exceed
/// `Lc = 255` (see [`MAC_WRITE_CHUNK`]).
///
/// Wire (per APDU): `90 8D 00 00 <Lc> FileNo Offset(3 LE) Length(3 LE)
/// Data MACt(8) 00`. Response: `MACt(8)`, `91 00`. Each APDU is its own
/// authenticated command: own `MACt`, own `CmdCtr` increment.
pub(crate) async fn write_data_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    validate_header(file_no, offset, data.len())?;

    let mut written: usize = 0;
    let mut current_offset = offset;
    while written < data.len() {
        let end = (written + MAC_WRITE_CHUNK).min(data.len());
        write_data_mac_one_apdu(
            transport,
            channel,
            file_no,
            current_offset,
            &data[written..end],
        )
        .await?;
        // `current_offset + (end - written)` cannot overflow `U24_MAX`
        // because validate_header enforced both `offset ≤ U24_MAX` and
        // `data.len() ≤ U24_MAX`, and `offset + data.len()` cannot
        // exceed `2 * U24_MAX < u32::MAX`. wrapping_add is defensive.
        current_offset = current_offset.wrapping_add((end - written) as u32);
        written = end;
    }
    Ok(())
}

async fn write_data_mac_one_apdu<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    let header = build_header(file_no, offset, data.len() as u32);

    let body = channel
        .send_mac(transport, 0x8D, 0x00, 0x00, &header, data)
        .await?;
    // WriteData response carries no encrypted data - only the MACt
    // which send_mac already verified and stripped.
    if !body.is_empty() {
        return Err(SessionError::UnexpectedLength {
            got: body.len(),
            expected: 0,
        });
    }
    Ok(())
}

/// `WriteData` in `CommMode.FULL` (§9.1.10).
///
/// Splits into multiple APDUs when the command body would exceed
/// `Lc = 255` (see [`FULL_WRITE_CHUNK`]). Each APDU is its own
/// authenticated command: own padding, encryption, `MACt`, and `CmdCtr`
/// increment.
///
/// Wire (per APDU): `90 8D 00 00 <Lc> FileNo Offset(3 LE) Length(3 LE)
/// E(Data||pad) MACt(8) 00`. Response: `MACt(8)`, `91 00` - no encrypted
/// data in the response (§10.8.2 Table 82: "No response data").
///
/// Encryption is applied to `CmdData` only (§9.1.10 Figure 9): the
/// header (`FileNo Offset Length`) is sent in the clear and included in
/// the MAC input, while the `Data` portion is padded with ISO/IEC 9797-1
/// Method 2, encrypted with `SesAuthENCKey`, and then MAC'd together
/// with the header.
pub(crate) async fn write_data_full<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    validate_header(file_no, offset, data.len())?;

    let mut written: usize = 0;
    let mut current_offset = offset;
    while written < data.len() {
        let end = (written + FULL_WRITE_CHUNK).min(data.len());
        write_data_full_one_apdu(
            transport,
            channel,
            file_no,
            current_offset,
            &data[written..end],
        )
        .await?;
        current_offset = current_offset.wrapping_add((end - written) as u32);
        written = end;
    }
    Ok(())
}

async fn write_data_full_one_apdu<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    let header = build_header(file_no, offset, data.len() as u32);

    // ISO/IEC 9797-1 Method 2 padding: data || 0x80 || 0x00..
    let padded_len = (data.len() + 1).div_ceil(BLOCK) * BLOCK;
    validate_body_len(7 + padded_len + MAC_LEN)?;

    // Build padded plaintext in a stack buffer. Max plaintext limited by
    // the 255-byte APDU body: 255 - 7(header) - 8(MAC) = 240 bytes of
    // ciphertext, i.e. 240 bytes padded (15 full blocks).
    let mut padded = [0u8; 240];
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;
    // Rest is already 0x00.

    let ct = &mut padded[..padded_len];
    channel.encrypt_command(ct)?;

    // MAC over Cmd || CmdCtr || TI || CmdHeader || E(CmdData).
    let mac = channel.compute_cmd_mac(0x8D, &header, ct);

    // Assemble APDU.
    let lc = (7 + ct.len() + MAC_LEN) as u8;
    let apdu_len = 5 + 7 + ct.len() + MAC_LEN + 1;
    let mut apdu = [0u8; 5 + MAX_APDU_BODY + 1];
    apdu[..5].copy_from_slice(&[0x90, 0x8D, 0x00, 0x00, lc]);
    apdu[5..12].copy_from_slice(&header);
    let mut pos = 12;
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

    // Response is MACt(8) only - no encrypted RespData (§10.8.2 Table 82).
    channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{
        Exchange, TestTransport, aes_key3_mac_state_hw, aes_key3_state_hw, block_on, hex_array,
        hex_bytes, lrp_key3_mac_state_hw, lrp_key3_state_hw,
    };
    use alloc::vec;
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

    /// Plain `WriteData` frames header and data correctly.
    ///
    /// Writes 4 bytes to file 02h at offset 0.
    /// `90 8D 00 00 0B 02 000000 04000000 DEADBEEF 00`.
    #[test]
    fn write_data_plain_frames_header_and_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let expected = hex_bytes("908D00000B02000000040000DEADBEEF00");
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x91, 0x00)]);
        block_on(write_data_plain(&mut transport, 0x02, 0, &data)).expect("plain write");
        assert_eq!(transport.remaining(), 0);
    }

    /// Offset and length are encoded 3-byte little-endian per Table 81.
    #[test]
    fn write_data_plain_encodes_offset_and_length_le() {
        // offset = 0x000010, length = 2 → header = 03 100000 020000
        let data = [0x55, 0xAA];
        let expected = hex_bytes("908D0000090310000002000055AA00");
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x91, 0x00)]);
        block_on(write_data_plain(&mut transport, 0x03, 0x10, &data)).expect("plain write");
    }

    /// PERMISSION_DENIED (`91 9D`, Table 83) surfaces as `ErrorResponse`.
    #[test]
    fn write_data_plain_surfaces_permission_denied() {
        let data = [0x01];
        let expected = hex_bytes("908D000008020000000100000100");
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x91, 0x9D)]);
        match block_on(write_data_plain(&mut transport, 0x02, 0, &data)) {
            Err(SessionError::ErrorResponse(ResponseStatus::PermissionDenied)) => (),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn write_data_plain_rejects_empty_data_without_transmit() {
        let mut transport = TestTransport::new([]);
        match block_on(write_data_plain(&mut transport, 0x02, 0, &[])) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "data.len()",
                value: 0,
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for empty data, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn write_data_plain_rejects_oversized_offset_without_transmit() {
        let data = [0x01];
        let mut transport = TestTransport::new([]);
        match block_on(write_data_plain(&mut transport, 0x02, U24_MAX + 1, &data)) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "offset",
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for offset, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn write_data_plain_rejects_apdu_body_overflow_without_transmit() {
        let data = [0u8; WRITE_DATA_MAX_BODY + 1];
        let mut transport = TestTransport::new([]);
        match block_on(write_data_plain(&mut transport, 0x02, 0, &data)) {
            Err(SessionError::ApduBodyTooLarge { got: 256, max: 255 }) => (),
            other => panic!("expected ApduBodyTooLarge, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    /// `CommMode.MAC` round-trip with hand-computed command + response MACs.
    ///
    /// Pins the framing: `90 8D 00 00 <Lc> Header Data MACt(8) 00`,
    /// response `MACt(8)`.
    #[test]
    fn write_data_mac_roundtrip_advances_counter() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let data: Vec<u8> = (0..16u8).collect();
        let header = build_header(0x02, 0, 16);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x8D);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            input.extend_from_slice(&data);
            suite.mac(&input)
        };

        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00); // RC
            input.extend_from_slice(&1u16.to_le_bytes()); // CmdCtr+1
            input.extend_from_slice(&ti);
            // No RespData for WriteData
            suite.mac(&input)
        };

        // Lc = 7(header) + 16(data) + 8(MAC) = 31 = 0x1F
        let mut expected_apdu = Vec::from([0x90, 0x8D, 0x00, 0x00, 0x1F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&data);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_mac, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_mac(&mut transport, &mut ch, 0x02, 0, &data).await
        })
        .expect("MAC write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Reject a bad `WriteData` response MAC.
    #[test]
    fn write_data_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let data = [0xAAu8; 4];
        let header = build_header(0x02, 0, 4);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x8D);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            input.extend_from_slice(&data);
            suite.mac(&input)
        };

        let mut bad_resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };
        bad_resp_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0x8D, 0x00, 0x00, 0x13]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&data);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &bad_resp_mac, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_mac(&mut transport, &mut ch, 0x02, 0, &data).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// Replay the AN12196 §5.8.2 `WriteData` `CommMode.FULL` vector.
    ///
    /// AN12196 Table 17 writes 128 bytes to file 02h at offset 0: the
    /// 83-byte NDEF record followed by 45 zero bytes. Session keys and
    /// TI are carried over from the §5.6 `AuthenticateEV2First`
    /// transcript; `CmdCtr` starts at 0.
    ///
    /// All hex values are taken verbatim from AN12196 rev 2.0.
    #[test]
    fn write_data_full_an12196_vector() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti: [u8; 4] = hex_array("9D00C4DF");

        // Step 7: 128 bytes of file data (83-byte NDEF record + 45 zero
        // bytes). CmdHeader Length = 0x80 = 128.
        let mut data = hex_bytes(
            "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D\
             3030303030303030303030303030303030303030303030303030303030303030\
             26633D30303030303030303030303030303030",
        );
        data.resize(128, 0x00);
        assert_eq!(data.len(), 128);

        // Step 15: expected C-APDU.
        let expected_apdu = hex_bytes(
            "908D00009F02000000800000\
             421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768BF\
             E596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BCFA\
             658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D651A\
             3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7BB\
             BEF0FD971FF532C3A802AF745660F2B4D1D9A8499661EBF300",
        );

        // Step 17: R-APDU body (MACt before 9100).
        let resp_body = hex_bytes("FC222E5F7A542452");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(&mut transport, &mut ch, 0x02, 0, &data).await
        })
        .expect("FULL write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// FULL-mode round-trip with a small payload that needs padding.
    ///
    /// 4 bytes of user data → 16 bytes after M2 padding → one cipher
    /// block. Exercises the padding + encrypt + MAC path for a sub-block
    /// payload.
    #[test]
    fn write_data_full_roundtrip_small_payload() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let header = build_header(0x03, 0, 4);

        // Pad: DEADBEEF 80 000000 00000000 00000000
        let mut padded = [0u8; 16];
        padded[..4].copy_from_slice(&data);
        padded[4] = 0x80;
        let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
        enc_suite.encrypt(Direction::Command, &ti, 0, &mut padded);
        let ciphertext = padded;

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x8D);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        // Lc = 7 + 16 + 8 = 31 = 0x1F
        let mut expected_apdu = Vec::from([0x90, 0x8D, 0x00, 0x00, 0x1F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&ciphertext);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_mac, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(&mut transport, &mut ch, 0x03, 0, &data).await
        })
        .expect("FULL write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// FULL mode with exactly 16 bytes of data (block-aligned).
    ///
    /// 16 bytes of data + M2 padding → 32 bytes of ciphertext (padding
    /// adds a full extra block when the plaintext is already aligned).
    #[test]
    fn write_data_full_block_aligned_gets_extra_padding_block() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let data: Vec<u8> = (0..16u8).collect();
        let header = build_header(0x02, 0, 16);

        // 16 bytes + 0x80 + 15 zeros = 32 bytes
        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(&data);
        padded[16] = 0x80;
        let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
        enc_suite.encrypt(Direction::Command, &ti, 0, &mut padded);
        let ciphertext = padded;

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x8D);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        // Lc = 7 + 32 + 8 = 47 = 0x2F
        let mut expected_apdu = Vec::from([0x90, 0x8D, 0x00, 0x00, 0x2F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&ciphertext);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_mac, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(&mut transport, &mut ch, 0x02, 0, &data).await
        })
        .expect("FULL write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `WriteData` (AES Key3 session).
    ///
    /// TI=085BC941, CmdCtr = 15 (after the full read at counter 14). Writes
    /// `DEADBEEF01020304` to proprietary file 0x03 at offset 0.
    #[test]
    fn write_data_full_hw_aes() {
        let mut state = aes_key3_state_hw(15);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes(
                "908D00001F03000000080000AA72F5E4A3E15A325D0D3E03D25850AF583D86603323DBE200",
            ),
            &hex_bytes("1311AC9B19446236"),
            0x91,
            0x00,
        )]);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(
                &mut transport,
                &mut ch,
                0x03,
                0,
                &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            )
            .await
        })
        .expect("hw AES full write must succeed");

        assert_eq!(state.counter(), 16);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `WriteData` (LRP Key3 session).
    ///
    /// TI=AFF75859, CmdCtr = 1 (after the full read at counter 0). Writes
    /// `DEADBEEF01020304` to proprietary file 0x03 at offset 0.
    #[test]
    fn write_data_full_hw_lrp() {
        let mut state = lrp_key3_state_hw(1, 9);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes(
                "908D00001F030000000800000CE1C30B270CCA4C1CCAF19A2B76E115D9C09145D6E3B56A00",
            ),
            &hex_bytes("AA1EC0DD97474DB9"),
            0x91,
            0x00,
        )]);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(
                &mut transport,
                &mut ch,
                0x03,
                0,
                &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            )
            .await
        })
        .expect("hw LRP full write must succeed");

        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured MAC-mode `WriteData` (AES Key3 session).
    ///
    /// TI=59237C63, CmdCtr = 0. Writes `DEADBEEF01020304` to proprietary file
    /// 0x03 at offset 0.
    #[test]
    fn write_data_mac_hw_aes() {
        let mut state = aes_key3_mac_state_hw(0);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("908D00001703000000080000DEADBEEF0102030451648BF7E220359A00"),
            &hex_bytes("D00E5F086A574F15"),
            0x91,
            0x00,
        )]);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_mac(
                &mut transport,
                &mut ch,
                0x03,
                0,
                &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            )
            .await
        })
        .expect("hw AES MAC write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured MAC-mode `WriteData` (LRP Key3 session).
    ///
    /// TI=4F4B4865, CmdCtr = 0. Writes `DEADBEEF01020304` to proprietary file
    /// 0x03 at offset 0.
    #[test]
    fn write_data_mac_hw_lrp() {
        let mut state = lrp_key3_mac_state_hw(0);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("908D00001703000000080000DEADBEEF01020304CDCA0B30BFF1176400"),
            &hex_bytes("CF706129C172629E"),
            0x91,
            0x00,
        )]);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_mac(
                &mut transport,
                &mut ch,
                0x03,
                0,
                &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            )
            .await
        })
        .expect("hw LRP MAC write must succeed");

        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Writing 256 bytes in `CommMode.MAC` exceeds the 255-byte short-`Lc`
    /// budget once the 7-byte header and 8-byte `MACt` are added, so it
    /// must split into two independent `WriteData` APDUs at offsets 0
    /// and 240. Verifies the chunk loop emits both APDUs in order and
    /// advances `CmdCtr` once per APDU.
    #[test]
    fn write_data_mac_chunks_at_240_byte_boundary() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let payload: Vec<u8> = (0..=255u8).collect();

        let build_exchange = |ctr: u16, off: u32, data: &[u8]| -> (Vec<u8>, Vec<u8>) {
            let header = build_header(0x02, off, data.len() as u32);
            let cmd_mac = {
                let mut input = Vec::new();
                input.push(0x8D);
                input.extend_from_slice(&ctr.to_le_bytes());
                input.extend_from_slice(&ti);
                input.extend_from_slice(&header);
                input.extend_from_slice(data);
                suite.mac(&input)
            };
            let resp_mac = {
                let mut input = Vec::new();
                input.push(0x00);
                input.extend_from_slice(&(ctr + 1).to_le_bytes());
                input.extend_from_slice(&ti);
                suite.mac(&input)
            };
            let lc = (7 + data.len() + MAC_LEN) as u8;
            let mut apdu = Vec::from([0x90u8, 0x8D, 0x00, 0x00, lc]);
            apdu.extend_from_slice(&header);
            apdu.extend_from_slice(data);
            apdu.extend_from_slice(&cmd_mac);
            apdu.push(0x00);
            (apdu, resp_mac.to_vec())
        };

        let (apdu1, resp1) = build_exchange(0, 0, &payload[..240]);
        let (apdu2, resp2) = build_exchange(1, 240, &payload[240..]);

        let mut transport = TestTransport::new([
            Exchange::new(&apdu1, &resp1, 0x91, 0x00),
            Exchange::new(&apdu2, &resp2, 0x91, 0x00),
        ]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_mac(&mut transport, &mut ch, 0x02, 0, &payload).await
        })
        .expect("chunked MAC write must succeed");

        assert_eq!(state.counter(), 2, "two APDUs must each advance CmdCtr");
        assert_eq!(transport.remaining(), 0);
    }

    /// Writing 256 bytes in `CommMode.FULL` must split at the 239-byte
    /// plaintext boundary (240-byte ciphertext after M2 padding). Each
    /// chunk is a fully independent FULL-mode write with its own
    /// padding, encryption, MAC, and `CmdCtr` increment.
    #[test]
    fn write_data_full_chunks_at_239_byte_boundary() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let payload: Vec<u8> = (0..=255u8).collect();

        let build_exchange =
            |ctr: u16, off: u32, plain: &[u8], padded_len: usize| -> (Vec<u8>, Vec<u8>) {
                let header = build_header(0x02, off, plain.len() as u32);
                // ISO/IEC 9797-1 Method 2 padding then encrypt with command IV.
                let mut padded = vec![0u8; padded_len];
                padded[..plain.len()].copy_from_slice(plain);
                padded[plain.len()] = 0x80;
                let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
                enc_suite.encrypt(Direction::Command, &ti, ctr, &mut padded);
                let cmd_mac = {
                    let mut input = Vec::new();
                    input.push(0x8D);
                    input.extend_from_slice(&ctr.to_le_bytes());
                    input.extend_from_slice(&ti);
                    input.extend_from_slice(&header);
                    input.extend_from_slice(&padded);
                    suite.mac(&input)
                };
                let resp_mac = {
                    let mut input = Vec::new();
                    input.push(0x00);
                    input.extend_from_slice(&(ctr + 1).to_le_bytes());
                    input.extend_from_slice(&ti);
                    suite.mac(&input)
                };
                let lc = (7 + padded.len() + MAC_LEN) as u8;
                let mut apdu = Vec::from([0x90u8, 0x8D, 0x00, 0x00, lc]);
                apdu.extend_from_slice(&header);
                apdu.extend_from_slice(&padded);
                apdu.extend_from_slice(&cmd_mac);
                apdu.push(0x00);
                (apdu, resp_mac.to_vec())
            };

        // 239 bytes of plaintext → 240-byte ciphertext.
        let (apdu1, resp1) = build_exchange(0, 0, &payload[..239], 240);
        // 17 bytes of plaintext → 32-byte ciphertext (sentinel forces 2nd block).
        let (apdu2, resp2) = build_exchange(1, 239, &payload[239..], 32);

        let mut transport = TestTransport::new([
            Exchange::new(&apdu1, &resp1, 0x91, 0x00),
            Exchange::new(&apdu2, &resp2, 0x91, 0x00),
        ]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            write_data_full(&mut transport, &mut ch, 0x02, 0, &payload).await
        })
        .expect("chunked FULL write must succeed");

        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }
}
