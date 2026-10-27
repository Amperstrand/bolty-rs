// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::Transport;
use crate::session::SessionError;
use crate::types::ResponseCode;

/// ISO/IEC 7816-4 DF name of the NTAG 424 DNA NDEF application
/// (NT4H2421Gx §8.2.2).
pub(crate) const NDEF_APPLICATION_DF_NAME: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// Maximum DF name length per ISO/IEC 7816-4.
const MAX_DF_NAME_LEN: usize = 16;

/// Select a DF by name.
///
/// Uses `ISOSelectFile` (NT4H2421Gx §10.9.1, `CLA=00 INS=A4 P1=04
/// P2=00`).
///
/// Panics if `df_name` is empty or longer than 16 bytes - the only
/// in-tree callers pass fixed, known-good constants.
pub(crate) async fn iso_select_df_by_name<T: Transport>(
    transport: &mut T,
    df_name: &[u8],
) -> Result<(), SessionError<T::Error>> {
    assert!(
        (1..=MAX_DF_NAME_LEN).contains(&df_name.len()),
        "DF name must be 1..=16 bytes per ISO/IEC 7816-4",
    );

    let mut apdu = [0u8; 5 + MAX_DF_NAME_LEN + 1];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = df_name.len() as u8;
    apdu[5..5 + df_name.len()].copy_from_slice(df_name);
    apdu[5 + df_name.len()] = 0x00;
    let apdu = &apdu[..5 + df_name.len() + 1];

    let r = transport.transmit(apdu).await?;
    let code = ResponseCode::iso(r.sw1, r.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok(())
}

/// Select an EF by File Identifier.
///
/// Uses `ISOSelectFile` (`CLA=00 INS=A4 P1=00 P2=0C`,
/// NT4H2421Gx §10.9.1).
///
/// P2=`0C` suppresses the response data (no FCI template). The NDEF
/// application must already be selected before calling this (§8.2.1).
pub(crate) async fn iso_select_ef_by_fid<T: Transport>(
    transport: &mut T,
    file_id: u16,
) -> Result<(), SessionError<T::Error>> {
    let fid = file_id.to_be_bytes();
    // 00 A4 00 0C 02 <FID_HI> <FID_LO>  - no Le (P2=0Ch suppresses response)
    let apdu = [0x00, 0xA4, 0x00, 0x0C, 0x02, fid[0], fid[1]];
    let r = transport.transmit(&apdu).await?;
    let code = ResponseCode::iso(r.sw1, r.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok(())
}

/// Select the NDEF application (§8.2.2). After POR the PICC level (MF)
/// is active and the AppKeys/files are not reachable; callers that need
/// `AuthenticateEV2First`, `Read/Write`, `ChangeFileSettings`, etc. must
/// select this DF first, otherwise the PICC answers `9140 NO_SUCH_KEY`
/// (§8.2.1).
pub(crate) async fn select_ndef_application<T: Transport>(
    transport: &mut T,
) -> Result<(), SessionError<T::Error>> {
    iso_select_df_by_name(transport, &NDEF_APPLICATION_DF_NAME).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionError;
    use crate::testing::{Exchange, TestTransport, block_on};
    use crate::types::ResponseStatus;

    /// APDU and `90 00` response validated on real NTAG 424 DNA hardware.
    #[test]
    fn select_ndef_application_issues_spec_apdu() {
        let mut transport = TestTransport::new([Exchange::new(
            // NT4H2421Gx §10.9.1: 00 A4 04 00 07 D2 76 00 00 85 01 01 00.
            &[
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            &[],
            0x90,
            0x00,
        )]);
        block_on(select_ndef_application(&mut transport)).expect("9000 must succeed");
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn select_surfaces_iso_error() {
        let mut transport = TestTransport::new([Exchange::new(
            &[
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            &[],
            0x6A,
            0x82,
        )]);
        match block_on(select_ndef_application(&mut transport)) {
            Err(SessionError::ErrorResponse(ResponseStatus::FileOrApplicationNotFound)) => (),
            other => panic!("expected FileOrApplicationNotFound, got {other:?}"),
        }
    }
}
