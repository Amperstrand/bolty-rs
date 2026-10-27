// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! `ISOUpdateBinary` command - NT4H2421Gx §10.9.3.
//!
//! ISO/IEC 7816-4 `UPDATE BINARY` (`CLA=00 INS=D6`). The command is
//! always `CommMode.Plain`: §10.9.3 explicitly states "the command is
//! only possible with CommMode.Plain". While the PICC is in
//! `AuthenticatedEV2` / `AuthenticatedLRP` state the command is
//! rejected with `SW=6982h` ("security status not satisfied"),
//! analogous to `ISOReadBinary` (§10.9.2 Table 89).
//!
//! P1/P2 addressing is identical to `ISOReadBinary`: either a short
//! FileID in `P1[7]=1, P1[4..0]=SFID` with an 8-bit offset in `P2`,
//! or a 15-bit offset across `P1`/`P2` referencing the currently
//! selected EF.

use crate::Transport;
use crate::session::SessionError;
use crate::types::ResponseCode;

/// Maximum data length per ISO short-form APDU.
///
/// `Lc` is a single byte so the maximum payload is 255 bytes. In
/// practice the NTAG 424 DNA StandardData files are at most 256 bytes
/// (§8.2.1 Table 68), which always fits.
const ISO_UPDATE_BINARY_MAX: usize = 255;

/// Write file bytes with `ISOUpdateBinary`.
///
/// `CLA=00 INS=D6`, NT4H2421Gx §10.9.3. `CommMode.Plain` only - no
/// secure-messaging variant exists.
///
/// Addressing follows ISO/IEC 7816-4 §5.1.2.1, identical to
/// `ISOReadBinary` (§10.9.2 Table 87, field `P1`):
///
/// - `short_file_id = None` - write to the currently-selected EF.
///   `P1-P2` (15 bits) encode `offset`, so `offset ≤ 0x7FFF`.
/// - `short_file_id = Some(0x01..=0x1E)` - select and target the EF
///   referenced by the short ISO FileID. `P1[7]=1`, `P1[4..0]=SFID`,
///   and `P2` carries an 8-bit `offset` (`0..=0xFF`).
///
/// The PICC response carries no data - only `SW1 SW2` (`9000h` on
/// success).
///
pub(crate) async fn iso_update_binary<T: Transport>(
    transport: &mut T,
    short_file_id: Option<u8>,
    offset: u16,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    if data.is_empty() {
        return Err(SessionError::InvalidCommandParameter {
            parameter: "data.len()",
            value: 0,
            reason: "must be non-zero",
        });
    }
    if data.len() > ISO_UPDATE_BINARY_MAX {
        return Err(SessionError::ApduBodyTooLarge {
            got: data.len(),
            max: ISO_UPDATE_BINARY_MAX,
        });
    }

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

    let lc = data.len() as u8;
    // Case 3 APDU: CLA INS P1 P2 Lc Data (no Le).
    let mut apdu = [0u8; 5 + ISO_UPDATE_BINARY_MAX];
    apdu[..5].copy_from_slice(&[0x00, 0xD6, p1, p2, lc]);
    apdu[5..5 + data.len()].copy_from_slice(data);

    let resp = transport.transmit(&apdu[..5 + data.len()]).await?;
    let code = ResponseCode::iso(resp.sw1, resp.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Exchange, TestTransport, block_on, hex_bytes};
    use crate::types::ResponseStatus;
    use alloc::vec;

    /// AN12196 §5.8.1 Table 16: ISOUpdateBinary writes 83 bytes of
    /// NDEF data at offset 0 in CommMode.Plain.
    #[test]
    fn iso_update_binary_an12196_vector() {
        let data = hex_bytes(
            "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D\
             3030303030303030303030303030303030303030303030303030303030303030\
             26633D30303030303030303030303030303030",
        );
        assert_eq!(data.len(), 83);

        // C-APDU: 00 D6 00 00 53 <data>
        let mut expected_apdu = vec![0x00, 0xD6, 0x00, 0x00, 0x53];
        expected_apdu.extend_from_slice(&data);

        let mut transport = TestTransport::new([Exchange::new(&expected_apdu, &[], 0x90, 0x00)]);
        block_on(iso_update_binary(&mut transport, None, 0, &data)).expect("update ok");
        assert_eq!(transport.remaining(), 0);
    }

    /// Short FileID addressing encodes `P1[7]=1, P1[4..0]=SFID`, `P2=offset`.
    #[test]
    fn short_file_id_encodes_sfid_in_p1() {
        let data = [0xAA; 4];
        // SFID 02h, offset 10 → P1=82h, P2=0Ah, Lc=04
        let expected = [0x00, 0xD6, 0x82, 0x0A, 0x04, 0xAA, 0xAA, 0xAA, 0xAA];
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x90, 0x00)]);
        block_on(iso_update_binary(&mut transport, Some(0x02), 10, &data)).expect("update ok");
    }

    /// 15-bit offset (no short FileID) splits across P1/P2 big-endian.
    #[test]
    fn fifteen_bit_offset_splits_across_p1_p2() {
        let data = [0x55; 2];
        // offset 0x0123 → P1=01, P2=23
        let expected = [0x00, 0xD6, 0x01, 0x23, 0x02, 0x55, 0x55];
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x90, 0x00)]);
        block_on(iso_update_binary(&mut transport, None, 0x0123, &data)).expect("update ok");
    }

    #[test]
    fn rejects_empty_data_without_transmit() {
        let mut transport = TestTransport::new([]);
        match block_on(iso_update_binary(&mut transport, None, 0, &[])) {
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
    fn rejects_oversized_offset_without_transmit() {
        let data = [0x01];
        let mut transport = TestTransport::new([]);
        match block_on(iso_update_binary(&mut transport, None, 0x8000, &data)) {
            Err(SessionError::InvalidCommandParameter {
                parameter: "offset",
                ..
            }) => (),
            other => panic!("expected InvalidCommandParameter for offset, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn rejects_apdu_body_overflow_without_transmit() {
        let data = [0u8; ISO_UPDATE_BINARY_MAX + 1];
        let mut transport = TestTransport::new([]);
        match block_on(iso_update_binary(&mut transport, None, 0, &data)) {
            Err(SessionError::ApduBodyTooLarge { got: 256, max: 255 }) => (),
            other => panic!("expected ApduBodyTooLarge, got {other:?}"),
        }
        assert_eq!(transport.remaining(), 0);
    }

    /// PICC returning `69 82` (security status not satisfied)
    /// surfaces as [`SessionError::ErrorResponse`].
    ///
    /// This is the expected behaviour when `ISOUpdateBinary` is
    /// attempted while in `AuthenticatedEV2`/`LRP` state (§10.9.3).
    #[test]
    fn security_status_not_satisfied_surfaces_as_error() {
        let data = [0x01];
        let expected = [0x00, 0xD6, 0x00, 0x00, 0x01, 0x01];
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x69, 0x82)]);
        match block_on(iso_update_binary(&mut transport, None, 0, &data)) {
            Err(SessionError::ErrorResponse(ResponseStatus::SecurityStatusNotSatisfied)) => (),
            other => panic!("expected SecurityStatusNotSatisfied, got {other:?}"),
        }
    }

    /// `6A 82` (file/application not found) surfaces correctly.
    #[test]
    fn file_not_found_surfaces_as_error() {
        let data = [0x01];
        let expected = [0x00, 0xD6, 0x00, 0x00, 0x01, 0x01];
        let mut transport = TestTransport::new([Exchange::new(&expected, &[], 0x6A, 0x82)]);
        match block_on(iso_update_binary(&mut transport, None, 0, &data)) {
            Err(SessionError::ErrorResponse(ResponseStatus::FileOrApplicationNotFound)) => (),
            other => panic!("expected FileOrApplicationNotFound, got {other:?}"),
        }
    }
}
