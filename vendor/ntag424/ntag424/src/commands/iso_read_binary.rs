// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::Transport;
use crate::session::SessionError;
use crate::types::ResponseCode;

/// Short-Le response cap (NT4H2421Gx §10.9.2, Table 87 footnote).
/// `Le = 00h` requests "the entire StandardData file", which the
/// single-byte Le field nonetheless limits to 256 bytes.
const ISO_READ_BINARY_MAX: usize = 256;

/// Read file bytes with `ISOReadBinary`.
///
/// This is `ISOReadBinary` (`CLA=00 INS=B0`, ISO/IEC 7816-4,
/// NT4H2421Gx §10.9.2) in `CommMode.Plain`; the command has no
/// secure-messaging variant.
///
/// Addressing follows ISO/IEC 7816-4 §5.1.1.1 (Table 87, field `P1`):
///
/// - `short_file_id = None` - read from the currently-selected EF. `P1-P2`
///   (15 bits) encode `offset`, so `offset` must be `≤ 0x7FFF`.
/// - `short_file_id = Some(0x01..=0x1E)` - select and target the EF
///   referenced by the short ISO FileID. `P1[7]=1`, `P1[4..0]=SFID`, and
///   `P2` carries an 8-bit `offset` (`0..=0xFF`).
///
/// The number of bytes requested is `min(buf.len(), 256)`; when that hits
/// the 256 cap the command asks for the entire file (`Le = 00h`). If the
/// file has fewer bytes available past `offset` the PICC returns a shorter
/// payload - the return value is the actual length copied into `buf`.
///
pub(crate) async fn iso_read_binary<T: Transport>(
    transport: &mut T,
    short_file_id: Option<u8>,
    offset: u16,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    if buf.is_empty() {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "buf.len()",
            value: 0,
            reason: "must be non-zero",
        });
    }
    let want = buf.len().min(ISO_READ_BINARY_MAX);
    let le = if want == ISO_READ_BINARY_MAX {
        0x00
    } else {
        want as u8
    };

    let (p1, p2) = match short_file_id {
        Some(sfid) => {
            if !(0x01..=0x1E).contains(&sfid) {
                return Err(SessionError::InvalidCommandParameter {
                    parameter: "short_file_id",
                    value: sfid as usize,
                    reason: "must be 0x01..=0x1E",
                });
            }
            if offset > u16::from(u8::MAX) {
                return Err(SessionError::InvalidCommandParameter {
                    parameter: "offset",
                    value: offset as usize,
                    reason: "must be <= 0xFF with a short FileID",
                });
            }
            (0x80 | sfid, offset as u8)
        }
        None => {
            if offset > 0x7FFF {
                return Err(SessionError::InvalidCommandParameter {
                    parameter: "offset",
                    value: offset as usize,
                    reason: "must be <= 0x7FFF",
                });
            }
            let be = offset.to_be_bytes();
            (be[0], be[1])
        }
    };

    let apdu = [0x00, 0xB0, p1, p2, le];
    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::iso(resp.sw1, resp.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let data = resp.data.as_ref();
    if data.len() > want {
        return Err(SessionError::UnexpectedLength {
            got: data.len(),
            expected: want,
        });
    }
    buf[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Exchange, TestTransport, block_on};
    use crate::types::ResponseStatus;

    /// No short FileID, offset 0, 32-byte read → `00 B0 00 00 20`.
    /// Payload is the factory CC file content from a real NTAG 424 DNA tag.
    #[test]
    fn reads_current_file_with_explicit_length() {
        #[rustfmt::skip]
        let payload: [u8; 32] = [
            0x00, 0x17, 0x20, 0x01, 0x00, 0x00, 0xFF, 0x04,
            0x06, 0xE1, 0x04, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x06, 0xE1, 0x05, 0x00, 0x80, 0x82, 0x83, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x00, 0x00, 0x20],
            &payload,
            0x90,
            0x00,
        )]);

        let mut buf = [0u8; 32];
        let n = block_on(iso_read_binary(&mut transport, None, 0, &mut buf)).expect("read ok");
        assert_eq!(n, 32);
        assert_eq!(buf, payload);
        assert_eq!(transport.remaining(), 0);
    }

    /// 15-bit `offset` splits across `P1`/`P2` big-endian: `0x0123 → 01 23`.
    #[test]
    fn encodes_15_bit_offset_across_p1_p2() {
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x01, 0x23, 0x10],
            &[0x55u8; 16],
            0x90,
            0x00,
        )]);

        let mut buf = [0u8; 16];
        let n = block_on(iso_read_binary(&mut transport, None, 0x0123, &mut buf)).expect("read ok");
        assert_eq!(n, 16);
        assert_eq!(buf, [0x55u8; 16]);
    }

    /// Encode a short-file-ID read for the whole file.
    ///
    /// Short ISO FileID `02h` (NDEF EF) with a 256-byte buffer encodes
    /// as `00 B0 82 05 00`; `Le = 00h` requests the whole file.
    #[test]
    fn short_file_id_selects_and_targets_ef() {
        let payload = [0xAAu8; 100];
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x82, 0x05, 0x00],
            &payload,
            0x90,
            0x00,
        )]);

        let mut buf = [0u8; 256];
        let n =
            block_on(iso_read_binary(&mut transport, Some(0x02), 5, &mut buf)).expect("read ok");
        assert_eq!(n, 100);
        assert_eq!(&buf[..100], &payload);
    }

    /// Clamp oversized buffers to the short-`Le` cap.
    ///
    /// The extra space past byte 256 is left untouched.
    /// Real NTAG 424 DNA NDEF file (factory state) returns 256 zero bytes.
    #[test]
    fn clamps_oversized_buffer_to_256() {
        let payload = [0x00u8; 256];
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x00, 0x00, 0x00],
            &payload,
            0x90,
            0x00,
        )]);

        let mut buf = [0xFFu8; 300];
        let n = block_on(iso_read_binary(&mut transport, None, 0, &mut buf)).expect("read ok");
        assert_eq!(n, 256);
        assert_eq!(&buf[..256], &payload);
        assert!(buf[256..].iter().all(|&b| b == 0xFF));
    }

    /// PICC returning `6A 82` (file/application not found, Table 89)
    /// surfaces as [`SessionError::ErrorResponse`].
    #[test]
    fn file_not_found_surfaces_as_error() {
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x00, 0x00, 0x08],
            &[],
            0x6A,
            0x82,
        )]);

        let mut buf = [0u8; 8];
        match block_on(iso_read_binary(&mut transport, None, 0, &mut buf)) {
            Err(SessionError::ErrorResponse(ResponseStatus::FileOrApplicationNotFound)) => (),
            other => panic!("expected FileOrApplicationNotFound, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_buffer_without_transmit() {
        let mut transport = TestTransport::new([]);
        let mut buf = [];
        match block_on(iso_read_binary(&mut transport, None, 0, &mut buf)) {
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
    fn rejects_oversized_offset_without_transmit() {
        let mut transport = TestTransport::new([]);
        let mut buf = [0u8; 1];
        match block_on(iso_read_binary(&mut transport, None, 0x8000, &mut buf)) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "offset",
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for offset, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    /// Reject overlong responses.
    ///
    /// A PICC returning more bytes than the caller asked for is surfaced
    /// as [`SessionError::UnexpectedLength`] rather than silently
    /// copying.
    #[test]
    fn rejects_overlong_response() {
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x00, 0x00, 0x04],
            &[0xDEu8, 0xAD, 0xBE, 0xEF, 0x00],
            0x90,
            0x00,
        )]);

        let mut buf = [0u8; 4];
        match block_on(iso_read_binary(&mut transport, None, 0, &mut buf)) {
            Err(SessionError::UnexpectedLength { got: 5, .. }) => (),
            other => panic!("expected UnexpectedLength {{ got: 5 }}, got {other:?}"),
        }
    }

    /// Surface ISO security-status failures.
    ///
    /// This covers a PICC returning `69 82` (security status not
    /// satisfied, Table 89) when reading a key-protected file without
    /// authentication.
    /// Confirmed on real NTAG 424 DNA hardware: Proprietary file (E105h)
    /// with ReadAccess=Key2 returns `69 82` for an unauthenticated read.
    #[test]
    fn security_status_not_satisfied_surfaces_as_error() {
        let mut transport = TestTransport::new([Exchange::new(
            &[0x00, 0xB0, 0x00, 0x00, 0x10],
            &[],
            0x69,
            0x82,
        )]);

        let mut buf = [0u8; 16];
        match block_on(iso_read_binary(&mut transport, None, 0, &mut buf)) {
            Err(SessionError::ErrorResponse(ResponseStatus::SecurityStatusNotSatisfied)) => (),
            other => panic!("expected SecurityStatusNotSatisfied, got {other:?}"),
        }
    }
}
