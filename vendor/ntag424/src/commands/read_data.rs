// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `ReadData` command - NT4H2421Gx §10.8.1.
//!
//! The command reads bytes from a StandardData file. Its CommMode is
//! defined per file (§8.2.3.5, Table 13), so three framings are
//! exposed here:
//!
//! - [`read_data_plain`] - no secure messaging. Used either without an
//!   authenticated session at all, or, per §8.2.3.3, inside an
//!   authenticated session when the only satisfied access condition is
//!   the free-access one (`Eh`).
//! - [`read_data_mac`] - `CommMode.MAC` (§9.1.9): command gets an
//!   8-byte `MACt` trailer, response data is plain with a trailing
//!   `MACt`.
//! - [`read_data_full`] - `CommMode.FULL` (§9.1.10): command has no
//!   data field so only the response is encrypted; response is
//!   `E(SesAuthENCKey; RespData || ISO/IEC 9797-1 M2 padding) || MACt`.
//!
//! In all variants the command header is `FileNo(1) || Offset(3 LE) ||
//! Length(3 LE)`; `length == 0` means "entire file from `offset`",
//! capped at the 256-byte short-`Le` response limit (§10.8.1 Table 78).
//!
//! ## Chunking
//!
//! The PICC only supports short-form APDUs and has no application-layer
//! chaining for `ReadData` (§8.4 Table 16, §8.5), so requests whose
//! response would exceed `Le = 256` are split across multiple APDUs at
//! successive offsets by [`read_data_mac`] and [`read_data_full`]. Each
//! per-APDU response carries its own `MACt` and advances `CmdCtr`. The
//! per-mode caps live on [`MAC_READ_CHUNK`] and [`FULL_READ_CHUNK`].

use crate::{
    Transport,
    commands::SecureChannel,
    commands::secure_channel::strip_m2_padding,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus},
};

/// Maximum `ReadData` response size.
///
/// This cap is dictated by the short-`Le` field (§10.8.1 Table 78 /
/// Table 79: "up to 256 byte including secure messaging").
const READ_DATA_RESP_CAP: usize = 256;

/// AES / LRP block size, used for FULL-mode padding arithmetic.
const BLOCK: usize = 16;

/// `MACt` trailer length (§9.1.3).
const MAC_LEN: usize = 8;

/// Max addressable file offset/length: 24-bit field per §10.8.1 Table 78.
const U24_MAX: u32 = 0x00FF_FFFF;

/// Max plaintext bytes per single `CommMode.MAC` `ReadData` APDU.
///
/// The response carries `data || MACt(8)`; the short-`Le` cap is 256 bytes
/// (§8.4 Table 16), leaving 248 bytes for plaintext.
const MAC_READ_CHUNK: u32 = 248;

/// Max plaintext bytes per single `CommMode.FULL` `ReadData` APDU.
///
/// Response is `E(data || M2 pad) || MACt(8)`. With `MACt = 8` the
/// ciphertext budget is `256 - 8 = 248`; rounding down to a 16-byte
/// boundary gives 240 ciphertext bytes, i.e. 15 cipher blocks. Since the
/// PICC always appends `0x80` and zero-pads to the next block, plaintext
/// of length `n` produces `(n+1).next_multiple_of(16)` ciphertext bytes:
/// 239 → 240 ✓, 240 → 256 ✗. So 239 is the per-APDU cap.
const FULL_READ_CHUNK: u32 = 239;

fn validate_request<E: core::error::Error + core::fmt::Debug>(
    file_no: u8,
    offset: u32,
    length: u32,
    buf_len: usize,
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
    if length > U24_MAX {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "length",
            value: length as usize,
            reason: "must fit 24 bits",
        });
    }
    if buf_len == 0 {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "buf.len()",
            value: 0,
            reason: "must be non-zero",
        });
    }
    if length != 0 && buf_len < length as usize {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "buf.len()",
            value: buf_len,
            reason: "must be at least the requested length",
        });
    }
    Ok(())
}

/// Build the 7-byte command header `FileNo || Offset(3 LE) || Length(3 LE)`.
fn build_header(file_no: u8, offset: u32, length: u32) -> [u8; 7] {
    debug_assert!(file_no <= 0x1F);
    debug_assert!(offset <= U24_MAX);
    debug_assert!(length <= U24_MAX);
    let o = offset.to_le_bytes();
    let l = length.to_le_bytes();
    [file_no, o[0], o[1], o[2], l[0], l[1], l[2]]
}

/// Compute the expected plain response size.
///
/// Keeps the destination buffer sizing consistent with `length`
/// (`0 == "whole file"` ⇒ use the full buffer).
fn want_plain_bytes(length: u32, buf_len: usize) -> usize {
    let requested = if length == 0 {
        buf_len
    } else {
        length as usize
    };
    requested.min(READ_DATA_RESP_CAP)
}

/// `ReadData` (INS `AD`, §10.8.1) in `CommMode.Plain`.
///
/// Wire: `90 AD 00 00 07 FileNo Offset(3 LE) Length(3 LE) 00`.
/// This helper only emits the plain APDU framing: it does not compute or
/// verify secure-messaging data itself. It is therefore safe to use either
/// unauthenticated or while authenticated when access was granted via a free
/// (`Eh`) access condition (§8.2.3.3). When called through an authenticated
/// session wrapper, that wrapper is responsible for advancing the tracked
/// command counter after a successful response.
///
/// Returns the number of bytes copied into `buf`.
pub(crate) async fn read_data_plain<T: Transport>(
    transport: &mut T,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    validate_request(file_no, offset, length, buf.len())?;
    let want = want_plain_bytes(length, buf.len());

    let header = build_header(file_no, offset, length);
    let mut apdu = [0u8; 5 + 7 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xAD, 0x00, 0x00, 0x07]);
    apdu[5..12].copy_from_slice(&header);
    // apdu[12] = 0x00 (Le).

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    // Truncate rather than error: once the PICC returned `91 00`, it has
    // accepted the command and (under active auth) advanced `CmdCtr`.
    // Returning an error here would desync the session. In practice
    // `data.len() <= want` because we sized the request from `want`.
    let data = resp.data.as_ref();
    let n = data.len().min(want).min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    Ok(n)
}

/// `ReadData` in `CommMode.MAC` (§9.1.9).
///
/// Splits into multiple APDUs when the response would exceed `Le = 256`
/// (see [`MAC_READ_CHUNK`]). `length == 0` ("whole file") is emulated by
/// issuing successive explicit-length APDUs sized off `buf.len()`,
/// stopping when the PICC returns a short response (file boundary) or
/// the buffer is full — the chunker never sends `Length = 0` itself,
/// because the PICC rejects it with `91 7E LengthError` once the
/// response would exceed the short-`Le` cap (observed on hardware).
///
/// Wire (per APDU): `90 AD 00 00 0F FileNo Offset(3 LE) Length(3 LE)
/// MACt(8) 00`; response `<plain data> <MACt(8)>`. Each APDU is its own
/// authenticated command: own `MACt`, own `CmdCtr` increment.
pub(crate) async fn read_data_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    validate_request(file_no, offset, length, buf.len())?;

    // `length == 0` ("fill the buffer, stop on EOF") is driven off
    // `buf.len()`; `length > 0` ("read exactly N bytes") off `length`.
    let target = if length == 0 {
        buf.len()
    } else {
        length as usize
    };

    let mut total: usize = 0;
    let mut current_offset = offset;
    while total < target {
        let chunk_usize = (target - total).min(MAC_READ_CHUNK as usize);
        let chunk = chunk_usize as u32;
        let n = read_data_mac_one_apdu(
            transport,
            channel,
            file_no,
            current_offset,
            chunk,
            &mut buf[total..total + chunk_usize],
        )
        .await?;
        total += n;
        if n < chunk_usize {
            // PICC returned a short response; treat as EOF and stop.
            break;
        }
        // `current_offset + chunk` cannot overflow `U24_MAX` because the
        // initial validate_request enforced `offset + length ≤ U24_MAX`
        // (offset and length each fit 24 bits), but be defensive anyway.
        current_offset = current_offset.wrapping_add(chunk);
    }
    Ok(total)
}

async fn read_data_mac_one_apdu<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    let want = want_plain_bytes(length, buf.len());

    let header = build_header(file_no, offset, length);
    let cmd_mac = channel.compute_cmd_mac(0xAD, &header, &[]);

    let mut apdu = [0u8; 5 + 7 + MAC_LEN + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xAD, 0x00, 0x00, 0x0F]);
    apdu[5..12].copy_from_slice(&header);
    apdu[12..20].copy_from_slice(&cmd_mac);
    // apdu[20] = 0x00 (Le).

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let data = channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    if data.len() > want {
        return Err(SessionError::UnexpectedLength {
            got: data.len(),
            expected: want,
        });
    }
    buf[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

/// `ReadData` in `CommMode.FULL` (§9.1.10).
///
/// Splits into multiple APDUs when the response would exceed `Le = 256`
/// (see [`FULL_READ_CHUNK`]). Each APDU is its own authenticated
/// command: own `MACt`, own `CmdCtr` increment, own padding/decryption.
///
/// Wire (per APDU): same request as MAC mode (no `CmdData`, so nothing
/// to encrypt on the command side). Response is
/// `E(SesAuthENCKey; RespData || 80 00..00) || MACt(8)` with the
/// response IV derived from `(TI, CmdCtr+1)` (§9.1.4). Verifies the
/// `MACt`, advances `CmdCtr`, decrypts the ciphertext, strips the
/// ISO/IEC 9797-1 Method 2 padding, and copies the plaintext into `buf`.
///
/// Padding rules (§9.1.4): the PICC always appends `0x80` then
/// zero-pads to the next 16-byte boundary - i.e. when the plaintext
/// length is already a multiple of 16, a whole extra padding block is
/// added.
pub(crate) async fn read_data_full<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    validate_request(file_no, offset, length, buf.len())?;

    // `length == 0` ("fill the buffer") is driven off `buf.len()`. The
    // chunker always emits explicit per-chunk lengths so each response
    // fits `Le = 256`; the caller must size `buf` exactly (no EOF
    // detection in FULL mode — the per-APDU helper pins each response
    // length).
    let target = if length == 0 {
        buf.len()
    } else {
        length as usize
    };

    let mut total: usize = 0;
    let mut current_offset = offset;
    while total < target {
        let chunk_usize = (target - total).min(FULL_READ_CHUNK as usize);
        let chunk = chunk_usize as u32;
        let n = read_data_full_one_apdu(
            transport,
            channel,
            file_no,
            current_offset,
            chunk,
            &mut buf[total..total + chunk_usize],
        )
        .await?;
        total += n;
        // FULL mode pins per-chunk `length` exactly, so a short
        // response would already have surfaced as `UnexpectedLength`.
        // No early-exit branch needed; just advance and continue.
        current_offset = current_offset.wrapping_add(chunk);
    }
    Ok(total)
}

async fn read_data_full_one_apdu<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    let header = build_header(file_no, offset, length);
    let cmd_mac = channel.compute_cmd_mac(0xAD, &header, &[]);

    let mut apdu = [0u8; 5 + 7 + MAC_LEN + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xAD, 0x00, 0x00, 0x0F]);
    apdu[5..12].copy_from_slice(&header);
    apdu[12..20].copy_from_slice(&cmd_mac);
    // apdu[20] = 0x00 (Le).

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let ciphertext = channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(SessionError::UnexpectedLength {
            got: ciphertext.len(),
            expected: ciphertext.len().max(1).next_multiple_of(BLOCK),
        });
    }

    // Decrypt in place in a local scratch buffer (≤ 256 bytes).
    let mut scratch = [0u8; READ_DATA_RESP_CAP];
    let ct_len = ciphertext.len();
    scratch[..ct_len].copy_from_slice(ciphertext);
    channel.decrypt_response(&mut scratch[..ct_len])?;

    // Strip ISO/IEC 9797-1 Method 2 padding: find the last 0x80 preceded
    // only by 0x00 bytes. The PICC always appends exactly one 0x80 and
    // zero-pads to the next 16-byte boundary, so the 0x80 must live in
    // the last block.
    //
    // NOTE on error semantics: the response MAC has already verified at
    // this point, so `CmdCtr` was advanced inside
    // `verify_response_mac_and_advance`. Malformed padding here is a
    // protocol-level anomaly (well-formed MAC over garbage plaintext
    // from a conforming PICC "can't happen"), not a MAC mismatch - so
    // surface it as `UnexpectedLength` and leave the (now-advanced)
    // counter alone; it matches the PICC's state.
    let Some(pad_start) = strip_m2_padding(&scratch[..ct_len]) else {
        return Err(SessionError::UnexpectedLength {
            got: ct_len,
            expected: ct_len,
        });
    };

    // If the caller pinned `length`, the plaintext must match it exactly.
    if length != 0 && pad_start != length as usize {
        return Err(SessionError::UnexpectedLength {
            got: pad_start,
            expected: length as usize,
        });
    }
    if pad_start > buf.len() {
        return Err(SessionError::UnexpectedLength {
            got: pad_start,
            expected: buf.len(),
        });
    }

    buf[..pad_start].copy_from_slice(&scratch[..pad_start]);
    Ok(pad_start)
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

    /// Replay a fixed plain `ReadData` exchange.
    ///
    /// Reads file 02h, 16 bytes at offset 0. The APDU is pinned
    /// byte-for-byte and the returned payload is copied verbatim.
    #[test]
    fn read_data_plain_frames_header_and_copies_payload() {
        let payload = [0xABu8; 16];
        // `90 AD 00 00 07 FileNo=02 Offset=000000 Length=100000 Le=00`.
        let expected = hex_bytes("90AD0000070200000010000000");
        let mut transport = TestTransport::new([Exchange::new(&expected, &payload, 0x91, 0x00)]);

        let mut buf = [0u8; 16];
        let n =
            block_on(read_data_plain(&mut transport, 0x02, 0, 16, &mut buf)).expect("plain read");
        assert_eq!(n, 16);
        assert_eq!(buf, payload);
    }

    /// Offset and length are encoded 3-byte little-endian per Table 78.
    #[test]
    fn read_data_plain_encodes_offset_and_length_little_endian() {
        // offset = 0x123456, length = 0x0000AB → `56 34 12` and `AB 00 00`.
        let expected = hex_bytes("90AD00000703563412AB000000");
        let payload = [0x77u8; 0xAB];
        let mut transport = TestTransport::new([Exchange::new(&expected, &payload, 0x91, 0x00)]);
        let mut buf = [0u8; 0xAB];
        let n = block_on(read_data_plain(
            &mut transport,
            0x03,
            0x12_3456,
            0x0000_00AB,
            &mut buf,
        ))
        .expect("plain read");
        assert_eq!(n, 0xAB);
    }

    /// PERMISSION_DENIED (`91 9D`, Table 80) surfaces as `ErrorResponse`.
    /// Status code confirmed on real NTAG 424 DNA hardware.
    #[test]
    fn read_data_plain_surfaces_permission_denied() {
        let expected = hex_bytes("90AD0000070200000010000000");
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x91, 0x9D)]);
        let mut buf = [0u8; 16];
        match block_on(read_data_plain(&mut transport, 0x02, 0, 16, &mut buf)) {
            Err(SessionError::ErrorResponse(ResponseStatus::PermissionDenied)) => (),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn read_data_plain_rejects_empty_buffer_without_transmit() {
        let mut transport = TestTransport::new([]);
        let mut buf = [];
        match block_on(read_data_plain(&mut transport, 0x02, 0, 0, &mut buf)) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "buf.len()",
                value: 0,
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for empty buffer, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn read_data_plain_rejects_oversized_offset_without_transmit() {
        let mut transport = TestTransport::new([]);
        let mut buf = [0u8; 1];
        match block_on(read_data_plain(
            &mut transport,
            0x02,
            U24_MAX + 1,
            0,
            &mut buf,
        )) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "offset",
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for offset, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn read_data_plain_rejects_short_buffer_without_transmit() {
        let mut transport = TestTransport::new([]);
        let mut buf = [0u8; 1];
        match block_on(read_data_plain(&mut transport, 0x02, 0, 2, &mut buf)) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "buf.len()",
                value: 1,
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for short buffer, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    /// `CommMode.MAC` round-trip with hand-computed command + response
    /// MACs over the §9.1.9 inputs. Pins the framing:
    /// `90 AD 00 00 0F FileNo Offset Length MACt(8) 00`, response
    /// `<plain data> <MACt(8)>`.
    #[test]
    fn read_data_mac_roundtrip_advances_counter() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let header = build_header(0x02, 0, 20);
        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xAD);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            suite.mac(&input)
        };

        let resp_data: Vec<u8> = (0..20u8).collect();
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&resp_data);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0xAD, 0x00, 0x00, 0x0F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = resp_data.clone();
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 32];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x02, 0, 20, &mut buf).await
        })
        .expect("MAC read must succeed");

        assert_eq!(n, 20);
        assert_eq!(&buf[..n], resp_data.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Reject a bad `ReadData` response MAC.
    ///
    /// Flipping one byte of the response trailer must surface as
    /// `ResponseMacMismatch` and leave `CmdCtr` pinned.
    #[test]
    fn read_data_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let header = build_header(0x02, 0, 20);
        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xAD);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            suite.mac(&input)
        };

        let resp_data: Vec<u8> = (0..20u8).collect();
        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&resp_data);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0xAD, 0x00, 0x00, 0x0F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = resp_data.clone();
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 32];
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x02, 0, 20, &mut buf).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// `length = 0` with `buf.len() > MAC_READ_CHUNK` must emit
    /// successive explicit-`Length` APDUs rather than one `Length = 0`
    /// APDU (the PICC rejects the latter once the response would exceed
    /// `Le = 256`).
    #[test]
    fn read_data_mac_chunks_when_length_zero_and_buf_exceeds_chunk() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let payload: Vec<u8> = (0..=255u8).collect();

        let build_exchange = |ctr: u16, off: u32, data: &[u8]| -> (Vec<u8>, Vec<u8>) {
            let header = build_header(0x02, off, data.len() as u32);
            let cmd_mac = {
                let mut input = Vec::new();
                input.push(0xAD);
                input.extend_from_slice(&ctr.to_le_bytes());
                input.extend_from_slice(&ti);
                input.extend_from_slice(&header);
                suite.mac(&input)
            };
            let resp_mac = {
                let mut input = Vec::new();
                input.push(0x00);
                input.extend_from_slice(&(ctr + 1).to_le_bytes());
                input.extend_from_slice(&ti);
                input.extend_from_slice(data);
                suite.mac(&input)
            };
            let mut apdu = Vec::from([0x90u8, 0xAD, 0x00, 0x00, 0x0F]);
            apdu.extend_from_slice(&header);
            apdu.extend_from_slice(&cmd_mac);
            apdu.push(0x00);
            let mut resp = data.to_vec();
            resp.extend_from_slice(&resp_mac);
            (apdu, resp)
        };

        let (apdu1, resp1) = build_exchange(0, 0, &payload[..MAC_READ_CHUNK as usize]);
        let (apdu2, resp2) = build_exchange(1, MAC_READ_CHUNK, &payload[MAC_READ_CHUNK as usize..]);

        let mut transport = TestTransport::new([
            Exchange::new(&apdu1, &resp1, 0x91, 0x00),
            Exchange::new(&apdu2, &resp2, 0x91, 0x00),
        ]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 256];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x02, 0, 0, &mut buf).await
        })
        .expect("chunked MAC read with length=0 must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf[..], payload.as_slice());
        assert_eq!(state.counter(), 2, "two APDUs must each advance CmdCtr");
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a FULL-mode `ReadData` round-trip.
    ///
    /// This covers a 20-byte plaintext becoming a 32-byte ciphertext
    /// after ISO/IEC 9797-1 Method 2 padding, with a trailing `MACt`
    /// over the ciphertext. It exercises decrypt and unpad.
    #[test]
    fn read_data_full_roundtrip_decrypts_and_unpads() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let header = build_header(0x03, 0, 20);
        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xAD);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            suite.mac(&input)
        };

        let plaintext: Vec<u8> = (0..20u8).collect();
        // ISO/IEC 9797-1 Method 2 pad to 32 bytes.
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(&plaintext);
        padded[20] = 0x80;
        let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
        enc_suite.encrypt(Direction::Response, &ti, 1, &mut padded);
        let ciphertext = padded;

        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0xAD, 0x00, 0x00, 0x0F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 32];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full(&mut transport, &mut ch, 0x03, 0, 20, &mut buf).await
        })
        .expect("FULL read must succeed");

        assert_eq!(n, 20);
        assert_eq!(&buf[..n], plaintext.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Preserve counter state on malformed FULL-mode padding.
    ///
    /// In FULL mode, a valid response MAC with decrypted plaintext that
    /// lacks the trailing `0x80` sentinel (§9.1.4 padding) "can't
    /// happen" for a conforming PICC. But when the PICC did return
    /// `91 00` with a verifying MAC it *also* advanced `CmdCtr`, so:
    /// - error is `UnexpectedLength` (not `ResponseMacMismatch` - the
    ///   MAC checked out), and
    /// - our `CmdCtr` must be advanced to stay in sync with the PICC.
    #[test]
    fn read_data_full_bad_padding_is_unexpected_length_and_advances_counter() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let header = build_header(0x03, 0, 16);
        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xAD);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&header);
            suite.mac(&input)
        };

        // 16 bytes of all-zero plaintext (no 0x80 sentinel).
        let mut padded = [0u8; 16];
        let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
        enc_suite.encrypt(Direction::Response, &ti, 1, &mut padded);
        let ciphertext = padded;

        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0xAD, 0x00, 0x00, 0x0F]);
        expected_apdu.extend_from_slice(&header);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 32];
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full(&mut transport, &mut ch, 0x03, 0, 16, &mut buf).await
        });
        match result {
            Err(SessionError::UnexpectedLength { got: 16, .. }) => (),
            other => panic!("expected UnexpectedLength, got {other:?}"),
        }
        assert_eq!(state.counter(), 1, "counter must track PICC state");
    }

    /// Replay a hardware-captured plain `ReadData` for the NDEF file (AES session).
    ///
    /// Plain-mode reads bypass secure channel framing, so no session state is
    /// needed. The 256-byte NDEF payload is returned verbatim.
    #[test]
    fn read_data_plain_hw_aes() {
        let payload = hex_bytes(
            "0047D1014355046578616D706C652E636F6D2F3F703D303030303030303030303030303030303030303030303030303030303030303026633D30303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(payload.len(), 256);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD0000070200000000000000"),
            &payload,
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 256];
        let n =
            block_on(read_data_plain(&mut transport, 0x02, 0, 0, &mut buf)).expect("must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf[..4], &[0x00, 0x47, 0xD1, 0x01]);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured plain `ReadData` for the NDEF file (LRP session).
    ///
    /// Plain-mode reads bypass secure channel framing; no session state needed.
    /// The 256-byte proprietary payload starts with `DEADBEEF`.
    #[test]
    fn read_data_plain_hw_lrp() {
        let payload = hex_bytes(
            "DEADBEEF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(payload.len(), 256);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD0000070200000000000000"),
            &payload,
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 256];
        let n =
            block_on(read_data_plain(&mut transport, 0x02, 0, 0, &mut buf)).expect("must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `ReadData` (AES Key3 session).
    ///
    /// TI=085BC941, CmdCtr = 14. Reads 128 bytes from file 0x03 using
    /// `Length = 0`. Drives `read_data_full_one_apdu` directly because
    /// the public `read_data_full` chunker always emits explicit
    /// per-chunk lengths and would not reproduce this capture.
    #[test]
    fn read_data_full_hw_aes() {
        let mut state = aes_key3_state_hw(14);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F03000000000000BBF64ADCF21BC5B900"),
            &hex_bytes(
                "C294BFF08106E2E92B7CCEE58C68C4D069E4B11F2922619CD15D61FB4169BADC9C0E7FFF3FFE4B3520B903157EED92FEFA517DC5E3EAAFDE94191DC9536DA8B5DBAEB57AC127D94FD2504FB137C3275B3EACDEC378708A1FC607636AC29F88CC6E25361BDD3F37733D0215888F91F8DC0C4298476469025C299B0E749A170B3894A0176AE285EEEABE522C834BF41C3598EFC29F5E3ABF67",
            ),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 128];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full_one_apdu(&mut transport, &mut ch, 0x03, 0, 0, &mut buf).await
        })
        .expect("hw AES full read must succeed");

        assert_eq!(n, 128);
        assert_eq!(&buf[..8], &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&buf[8..], &[0u8; 120]);
        assert_eq!(state.counter(), 15);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `ReadData` 8-byte readback (AES Key3 session).
    ///
    /// TI=085BC941, CmdCtr = 16 (after the write at counter 15). Verifies the
    /// written `DEADBEEF01020304` payload survived the write.
    #[test]
    fn read_data_full_readback_hw_aes() {
        let mut state = aes_key3_state_hw(16);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F030000000800008705F20A9AF5957800"),
            &hex_bytes("71DAFA7A0012584D37F8C9F3F656738FF345494D0F114867"),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 8];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full(&mut transport, &mut ch, 0x03, 0, 8, &mut buf).await
        })
        .expect("hw AES readback must succeed");

        assert_eq!(n, 8);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(state.counter(), 17);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `ReadData` (LRP Key3 session).
    ///
    /// TI=AFF75859, CmdCtr = 0. LRP counterpart to
    /// [`read_data_full_hw_aes`]; same rationale for targeting
    /// `read_data_full_one_apdu` directly.
    #[test]
    fn read_data_full_hw_lrp() {
        let mut state = lrp_key3_state_hw(0, 0);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F030000000000004346E1444E7A4B2600"),
            &hex_bytes(
                "C0D13D2E78879C91D6E52DD735DE47D3E9A5BD06D1D6B43C5992CB65FA9257AB430EC34DB3F380BA58026762AAE1C38ABED3C6AF50325C18D61F67342B878AF5583F8EFD4293B30BB911BD542AFC92E0D45FF26893282421D5D660EBE8C61C87D4A2D9EBEDE206D5D93ECCD9687E38CA20CE98AAC748B0927E786134815B7C4984FF3A86083FF52898176CE33AD81DFED2D76386A7B2F9B1",
            ),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 128];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full_one_apdu(&mut transport, &mut ch, 0x03, 0, 0, &mut buf).await
        })
        .expect("hw LRP full read must succeed");

        assert_eq!(n, 128);
        assert_eq!(&buf[..8], &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&buf[8..], &[0u8; 120]);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured Full-mode `ReadData` 8-byte readback (LRP Key3 session).
    ///
    /// TI=AFF75859, CmdCtr = 2 (after the write at counter 1). Verifies the
    /// written `DEADBEEF01020304` payload survived the write.
    #[test]
    fn read_data_full_readback_hw_lrp() {
        let mut state = lrp_key3_state_hw(2, 10);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F030000000800002086BC2A3CBAB30000"),
            &hex_bytes("A8F86E5BE27A1B0BA7D0CEF39092D585F38F94FB3F8275C2"),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 8];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full(&mut transport, &mut ch, 0x03, 0, 8, &mut buf).await
        })
        .expect("hw LRP readback must succeed");

        assert_eq!(n, 8);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(state.counter(), 3);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured MAC-mode `ReadData` 8-byte readback (AES Key3 session).
    ///
    /// TI=59237C63, CmdCtr = 1 (after the MAC write at counter 0). Verifies the
    /// written `DEADBEEF01020304` payload survived the write.
    #[test]
    fn read_data_mac_hw_aes() {
        let mut state = aes_key3_mac_state_hw(1);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F03000000080000D92404817565D2A900"),
            &hex_bytes("DEADBEEF010203042F36F240E65DB6CF"),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 8];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x03, 0, 8, &mut buf).await
        })
        .expect("hw AES MAC read must succeed");

        assert_eq!(n, 8);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// Replay a hardware-captured MAC-mode `ReadData` 8-byte readback (LRP Key3 session).
    ///
    /// TI=4F4B4865, CmdCtr = 1 (after the MAC write at counter 0). Verifies the
    /// written `DEADBEEF01020304` payload survived the write.
    #[test]
    fn read_data_mac_hw_lrp() {
        let mut state = lrp_key3_mac_state_hw(1);

        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("90AD00000F03000000080000B79542988C83E5C700"),
            &hex_bytes("DEADBEEF01020304BC7C18EB8C8ECA66"),
            0x91,
            0x00,
        )]);

        let mut buf = [0u8; 8];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x03, 0, 8, &mut buf).await
        })
        .expect("hw LRP MAC read must succeed");

        assert_eq!(n, 8);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }

    /// Reading 256 bytes in `CommMode.MAC` exceeds the 256-byte short-`Le`
    /// budget once the 8-byte `MACt` is added, so it must split into two
    /// independent `ReadData` APDUs at offsets 0 and 248. Verifies the
    /// chunk loop emits both APDUs in order, advances `CmdCtr` once per
    /// APDU, and assembles the full payload back into the caller's buffer.
    #[test]
    fn read_data_mac_chunks_at_248_byte_boundary() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        // Distinctive 256-byte payload so a misordered reassembly would
        // be caught by the buffer comparison.
        let payload: Vec<u8> = (0..=255u8).collect();

        let build_exchange = |ctr: u16, off: u32, len: u32, data: &[u8]| -> (Vec<u8>, Vec<u8>) {
            let header = build_header(0x02, off, len);
            let cmd_mac = {
                let mut input = Vec::new();
                input.push(0xAD);
                input.extend_from_slice(&ctr.to_le_bytes());
                input.extend_from_slice(&ti);
                input.extend_from_slice(&header);
                suite.mac(&input)
            };
            let resp_mac = {
                let mut input = Vec::new();
                input.push(0x00);
                input.extend_from_slice(&(ctr + 1).to_le_bytes());
                input.extend_from_slice(&ti);
                input.extend_from_slice(data);
                suite.mac(&input)
            };
            let mut apdu = Vec::from([0x90u8, 0xAD, 0x00, 0x00, 0x0F]);
            apdu.extend_from_slice(&header);
            apdu.extend_from_slice(&cmd_mac);
            apdu.push(0x00);
            let mut resp_body = data.to_vec();
            resp_body.extend_from_slice(&resp_mac);
            (apdu, resp_body)
        };

        let (apdu1, resp1) = build_exchange(0, 0, 248, &payload[..248]);
        let (apdu2, resp2) = build_exchange(1, 248, 8, &payload[248..]);

        let mut transport = TestTransport::new([
            Exchange::new(&apdu1, &resp1, 0x91, 0x00),
            Exchange::new(&apdu2, &resp2, 0x91, 0x00),
        ]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 256];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_mac(&mut transport, &mut ch, 0x02, 0, 256, &mut buf).await
        })
        .expect("chunked MAC read must succeed");

        assert_eq!(n, 256);
        assert_eq!(buf.as_slice(), payload.as_slice());
        assert_eq!(state.counter(), 2, "two APDUs must each advance CmdCtr");
        assert_eq!(transport.remaining(), 0);
    }

    /// Reading 256 bytes in `CommMode.FULL` exceeds the response budget
    /// once padding+MAC overhead is added, so it must split at the
    /// 239-byte plaintext boundary (240-byte ciphertext). Each chunk is a
    /// fully independent FULL-mode read with its own padding, MAC, and
    /// `CmdCtr` increment.
    #[test]
    fn read_data_full_chunks_at_239_byte_boundary() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let payload: Vec<u8> = (0..=255u8).collect();

        let build_exchange =
            |ctr: u16, off: u32, plain: &[u8], padded_len: usize| -> (Vec<u8>, Vec<u8>) {
                let header = build_header(0x03, off, plain.len() as u32);
                let cmd_mac = {
                    let mut input = Vec::new();
                    input.push(0xAD);
                    input.extend_from_slice(&ctr.to_le_bytes());
                    input.extend_from_slice(&ti);
                    input.extend_from_slice(&header);
                    suite.mac(&input)
                };
                // Build padded plaintext, encrypt with response IV at ctr+1.
                let mut padded = vec![0u8; padded_len];
                padded[..plain.len()].copy_from_slice(plain);
                padded[plain.len()] = 0x80;
                let mut enc_suite = AesSuite::from_keys(enc_key, mac_key);
                enc_suite.encrypt(Direction::Response, &ti, ctr + 1, &mut padded);
                let resp_mac = {
                    let mut input = Vec::new();
                    input.push(0x00);
                    input.extend_from_slice(&(ctr + 1).to_le_bytes());
                    input.extend_from_slice(&ti);
                    input.extend_from_slice(&padded);
                    suite.mac(&input)
                };
                let mut apdu = Vec::from([0x90u8, 0xAD, 0x00, 0x00, 0x0F]);
                apdu.extend_from_slice(&header);
                apdu.extend_from_slice(&cmd_mac);
                apdu.push(0x00);
                let mut resp_body = padded;
                resp_body.extend_from_slice(&resp_mac);
                (apdu, resp_body)
            };

        // 239 bytes of plaintext → 240-byte ciphertext (one M2 sentinel).
        let (apdu1, resp1) = build_exchange(0, 0, &payload[..239], 240);
        // 17 bytes of plaintext → 32-byte ciphertext (sentinel forces 2nd block).
        let (apdu2, resp2) = build_exchange(1, 239, &payload[239..], 32);

        let mut transport = TestTransport::new([
            Exchange::new(&apdu1, &resp1, 0x91, 0x00),
            Exchange::new(&apdu2, &resp2, 0x91, 0x00),
        ]);
        let mut state = authenticated_aes(enc_key, mac_key, ti, 0);

        let mut buf = [0u8; 256];
        let n = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_data_full(&mut transport, &mut ch, 0x03, 0, 256, &mut buf).await
        })
        .expect("chunked FULL read must succeed");

        assert_eq!(n, 256);
        assert_eq!(buf.as_slice(), payload.as_slice());
        assert_eq!(state.counter(), 2);
        assert_eq!(transport.remaining(), 0);
    }
}
