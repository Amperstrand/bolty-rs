// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use zeroize::Zeroizing;

use crate::Transport;
use crate::commands::authenticate::AuthResult;
use crate::crypto::ct_eq_16;
use crate::crypto::suite::{Direction, LrpSuite, SessionSuite};
use crate::session::SessionError;
use crate::types::{KeyNumber, ResponseCode, ResponseStatus};

/// `PCDCap2` we send in Part 1. Bit 1 of `PCDCap2.1` selects LRP mode;
/// the remaining bytes are not interpreted by the PICC (§9.2.5,
/// §10.4.3 Table 37). The PICC echoes this 6-byte value back inside the
/// encrypted `PICCData` for verification.
const PCDCAP2: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// `AuthMode` byte for LRP secure messaging.
///
/// This value appears in the Part 1 response (§10.4.3 Table 38).
const AUTH_MODE_LRP: u8 = 0x01;

/// `AuthenticateLRPNonFirst` (NT4H2421Gx §9.2.6, §10.4.4).
///
/// Re-authenticates within an already-active LRP session, deriving fresh
/// session keys while the PICC preserves TI and `CmdCtr`. `EncCtr` is reset
/// to 0 after NonFirst (§9.2.4, p. 30); `LrpSuite::derive` already
/// initialises `enc_ctr = 0`, so this happens naturally.
///
/// INS = `77h` (consistent with the First=`71h` / NonFirst=`77h` pattern;
/// see Table 22, p. 44). No `PCDcap2` or `LenCap` is exchanged (§9.2.6,
/// p. 32: "PCDCap2 and PDCap2 are not exchanged and validated").
///
/// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
pub(crate) async fn authenticate_ev2_non_first<T: Transport>(
    transport: &mut T,
    key_no: KeyNumber,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<LrpSuite, SessionError<T::Error>> {
    // Part 1: CLA=90 CMD=77 P1=00 P2=00 Lc=01 [KeyNo] Le=00.
    // No LenCap or PCDcap2 (§10.4.4, Table 43, p. 53).
    let part1_apdu = [0x90, 0x77, 0x00, 0x00, 0x01, key_no.as_byte(), 0x00];
    let r1 = transport.transmit(&part1_apdu).await?;
    let code = ResponseCode::desfire(r1.sw1, r1.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // Response: AuthMode (1, 01h = LRP) || RndB (16), plain (Table 44, p. 53).
    let data1 = r1.data.as_ref();
    if data1.len() != 17 {
        return Err(SessionError::UnexpectedLength {
            got: data1.len(),
            expected: 17,
        });
    }
    if data1[0] != AUTH_MODE_LRP {
        return Err(SessionError::AuthenticationMismatch);
    }
    let rnd_b: Zeroizing<[u8; 16]> = Zeroizing::new(data1[1..17].try_into().unwrap());

    // Derive the new session suite; enc_ctr = 0 (§9.2.4, p. 30).
    let suite = LrpSuite::derive(key, &rnd_a, &rnd_b);

    // PCDResponse = MAC_LRP(SesAuthMACKey; RndA || RndB), untruncated
    // (Table 46, p. 54; §9.2.5: "MACs are not truncated during authentication").
    let mut mac_input: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    mac_input[..16].copy_from_slice(&rnd_a);
    mac_input[16..].copy_from_slice(&*rnd_b);
    let pcd_response = suite.mac_full(&*mac_input);

    let part2_apdu = build_part2_apdu(&rnd_a, &pcd_response);
    let r2 = transport.transmit(&part2_apdu).await?;
    let code = ResponseCode::desfire(r2.sw1, r2.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // Response: PICCResponse [16 bytes] only - no PICCData block unlike First
    // (Table 47, p. 54; §9.2.6: "TI is not reset and not exchanged").
    let picc_response: [u8; 16] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
                expected: 16,
            })?;

    // Verify: MAC_LRP(SesAuthMACKey; RndB || RndA) == PICCResponse.
    let mut verify_input: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    verify_input[..16].copy_from_slice(&*rnd_b);
    verify_input[16..].copy_from_slice(&rnd_a);
    if !ct_eq_16(&suite.mac_full(&*verify_input), &picc_response) {
        return Err(SessionError::AuthenticationMismatch);
    }

    Ok(suite)
}

/// `AuthenticateLRPFirst` (NT4H2421Gx §9.2.5, §10.4.3).
///
/// Drives the two-part challenge/response handshake with the PICC using
/// the application key `key` at slot `key_no` and the caller-supplied
/// 16-byte random `rnd_a`. On success, returns the derived [`LrpSuite`]
/// session (with `EncCtr = 1`, per §9.2.4) and the 4-byte Transaction
/// Identifier chosen by the PICC.
///
/// The caller owns entropy: passing `rnd_a` in keeps this crate
/// `no_std`-clean and makes the handshake deterministically testable.
pub(crate) async fn authenticate_ev2_first<T: Transport>(
    transport: &mut T,
    key_no: KeyNumber,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<AuthResult<LrpSuite>, SessionError<T::Error>> {
    // Part 1: CLA=90 CMD=71 P1=00 P2=00 Lc=08
    //   [KeyNo | LenCap=06 | PCDcap2 (6 bytes)] Le=00.
    // LenCap=06 means all 6 PCDcap2 bytes are carried (§10.4.3, Table 37).
    let part1_apdu = [
        0x90,
        0x71,
        0x00,
        0x00,
        0x08,
        key_no.as_byte(),
        0x06,
        PCDCAP2[0],
        PCDCAP2[1],
        PCDCAP2[2],
        PCDCAP2[3],
        PCDCAP2[4],
        PCDCAP2[5],
        0x00, // Le
    ];
    let r1 = transport.transmit(&part1_apdu).await?;
    let code = ResponseCode::desfire(r1.sw1, r1.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // Response: AuthMode (1, 01h = LRP) || RndB (16), plain (Table 38).
    let data1 = r1.data.as_ref();
    if data1.len() != 17 {
        return Err(SessionError::UnexpectedLength {
            got: data1.len(),
            expected: 17,
        });
    }
    if data1[0] != AUTH_MODE_LRP {
        return Err(SessionError::AuthenticationMismatch);
    }
    let rnd_b: Zeroizing<[u8; 16]> = Zeroizing::new(data1[1..17].try_into().unwrap());

    // Derive the session suite once; reused for the PCDResponse MAC,
    // the PICCResponse MAC check, and the PICCData decrypt.
    let suite = LrpSuite::derive(key, &rnd_a, &rnd_b);

    // PCDResponse = MAC_LRP(SesAuthMACKey; RndA || RndB), untruncated
    // (§9.2.5: "MACs are not truncated during the authentication").
    let mut mac_input: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    mac_input[..16].copy_from_slice(&rnd_a);
    mac_input[16..].copy_from_slice(&*rnd_b);
    let pcd_response = suite.mac_full(&*mac_input);

    let part2_apdu = build_part2_apdu(&rnd_a, &pcd_response);
    let r2 = transport.transmit(&part2_apdu).await?;
    let code = ResponseCode::desfire(r2.sw1, r2.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    // Response: PICCData (16) || PICCResponse (16) (Table 41).
    let data2: [u8; 32] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
                expected: 32,
            })?;
    let picc_data: [u8; 16] = data2[..16].try_into().unwrap();
    let picc_response: [u8; 16] = data2[16..].try_into().unwrap();

    verify_and_extract_auth_result(suite, &rnd_a, &rnd_b, &picc_data, &picc_response)
}

/// Build the authentication Part 2 APDU.
///
/// The wire form is `90 AF 00 00 20 || RndA || PCDResponse || 00`
/// (§10.4.3 Table 40).
fn build_part2_apdu(rnd_a: &[u8; 16], pcd_response: &[u8; 16]) -> [u8; 38] {
    let mut apdu = [0u8; 38];
    apdu[0] = 0x90;
    apdu[1] = 0xAF;
    apdu[4] = 0x20;
    apdu[5..21].copy_from_slice(rnd_a);
    apdu[21..37].copy_from_slice(pcd_response);
    // apdu[37] = 0x00 (Le) - already zero
    apdu
}

/// Verify the Part 2 response and pull `TI` out of the decrypted
/// `PICCData`. Advances `suite.enc_ctr` from 0 to 1.
///
/// Checks performed, both must pass:
/// - `PICCResponse = MAC_LRP(SesAuthMACKey; RndB || RndA || PICCData)`,
///   untruncated (Table 41).
/// - `PICCData` at `EncCtr=0` decrypts to `TI || PDCap2 || PCDCap2`;
///   the trailing 6 bytes (echoed `PCDCap2`) must match what we sent
///   in Part 1 (§9.2.5: "PCDCap2 … sent back for verification").
fn verify_and_extract_auth_result<E: core::error::Error + core::fmt::Debug>(
    mut suite: LrpSuite,
    rnd_a: &[u8; 16],
    rnd_b: &[u8; 16],
    picc_data: &[u8; 16],
    picc_response: &[u8; 16],
) -> Result<AuthResult<LrpSuite>, SessionError<E>> {
    let mut verify_input: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    verify_input[..16].copy_from_slice(rnd_b);
    verify_input[16..32].copy_from_slice(rnd_a);
    verify_input[32..].copy_from_slice(picc_data);
    if !ct_eq_16(&suite.mac_full(&*verify_input), picc_response) {
        return Err(SessionError::AuthenticationMismatch);
    }

    // Single-block decrypt at EncCtr=0; advances to 1 (§9.2.4).
    let mut plain: Zeroizing<[u8; 16]> = Zeroizing::new(*picc_data);
    suite.decrypt(Direction::Response, &[0; 4], 0, &mut *plain);

    // plain = TI (4) || PDCap2 (6) || PCDCap2 (6). The PICC echoes the
    // PCDCap2 we sent; mismatch means the PICC didn't interpret Part 1
    // as we did, so reject the handshake.
    if plain[10..16] != PCDCAP2 {
        return Err(SessionError::AuthenticationMismatch);
    }

    let mut ti = [0u8; 4];
    ti.copy_from_slice(&plain[..4]);

    let mut pd_cap2 = [0u8; 6];
    pd_cap2.copy_from_slice(&plain[4..10]);

    let mut pcd_cap2 = [0u8; 6];
    pcd_cap2.copy_from_slice(&plain[10..16]);

    Ok(AuthResult {
        suite,
        ti,
        pd_cap2,
        pcd_cap2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex_array;

    #[derive(Debug)]
    struct NeverError;
    impl core::fmt::Display for NeverError {
        fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Ok(())
        }
    }
    impl core::error::Error for NeverError {}

    /// AN12321 §4, Table 2 - `AuthenticateLRPFirst` with key 0x03 (all-zero
    /// default value). Verifies the Part 2 APDU bytes (RndA || PCDResponse),
    /// the PICCResponse MAC check, TI extraction, and `EncCtr = 1` post-auth.
    ///
    /// Vectors from AN12321 pages 7–8.
    #[test]
    fn part2_apdu_and_verify_an12321_key3() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        let rnd_b: [u8; 16] = hex_array("56109A31977C855319CD4618C9D2AED2");

        // PCDResponse = MAC_LRP(SesAuthMACKey; RndA || RndB) from step 19.
        let pcd_response: [u8; 16] = hex_array("189B59DCEDC31A3D3F38EF8D4810B3B4");
        let part2 = build_part2_apdu(&rnd_a, &pcd_response);
        // Part 2 APDU: 90 AF 00 00 20 || RndA || PCDResponse || 00
        // Bytes from AN12321 Table 2 step 19 APDU.
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF00002074D7DF6A2CEC0B72B412DE0D2B1117E6189B59DCEDC31A3D3F38EF8D4810B3B400"
            ),
        );

        // PICCData and PICCResponse from step 20 of AN12321 Table 2.
        let picc_data: [u8; 16] = hex_array("F4FC209D9D60623588B299FA5D6B2D71");
        let picc_response: [u8; 16] = hex_array("0125F8547D9FB8D572C90D2C2A14E235");

        let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b);
        let auth_result = verify_and_extract_auth_result::<NeverError>(
            suite,
            &rnd_a,
            &rnd_b,
            &picc_data,
            &picc_response,
        )
        .expect("valid transcript should verify");

        // TI from step 25 of AN12321 Table 2.
        assert_eq!(auth_result.ti, hex_array::<4>("58EE9424"));
        assert_eq!(auth_result.pd_cap2, PCDCAP2);
        assert_eq!(auth_result.pcd_cap2, PCDCAP2);
        // EncCtr must be 1 after the one-block PICCData decryption in auth
        // (§9.2.4: "00000000h is already used for the response of part 2,
        // so the actual secure messaging starts from 00000001h").
        assert_eq!(auth_result.suite.enc_ctr(), 1);
    }

    /// Real NTAG 424 DNA hardware - `AuthenticateLRPFirst` with Key 0
    /// (all-zero factory default). Verifies the Part 2 APDU bytes
    /// (RndA || PCDResponse), the PICCResponse MAC check, TI extraction,
    /// and `EncCtr = 1` post-auth against an actual on-wire transcript.
    #[test]
    fn part2_apdu_and_verify_hw_key0() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("D1D85ACB0A57299BFEED443D832DAD0C");
        let rnd_b: [u8; 16] = hex_array("B40643A537D6B0ACD8E7816168CD85C1");

        // PCDResponse from wire (second 16 bytes of Part 2 data).
        let pcd_response: [u8; 16] = hex_array("23A13B80F26E481E4FAD3F3D75B14B7B");
        let part2 = build_part2_apdu(&rnd_a, &pcd_response);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF000020D1D85ACB0A57299BFEED443D832DAD0C23A13B80F26E481E4FAD3F3D75B14B7B00"
            ),
        );

        // PICCData || PICCResponse from Part 2 response.
        let picc_data: [u8; 16] = hex_array("1C8EE9654067C50B188BD7652CEA8ABF");
        let picc_response: [u8; 16] = hex_array("4DCAF2776C80ABACEC992D6DF2D6E4EE");

        let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b);

        // Verify our PCDResponse computation matches the wire data.
        let mut mac_input = [0u8; 32];
        mac_input[..16].copy_from_slice(&rnd_a);
        mac_input[16..].copy_from_slice(&rnd_b);
        assert_eq!(suite.mac_full(&mac_input), pcd_response);

        let auth_result = verify_and_extract_auth_result::<NeverError>(
            suite,
            &rnd_a,
            &rnd_b,
            &picc_data,
            &picc_response,
        )
        .expect("valid hardware transcript should verify");

        assert_eq!(auth_result.ti, hex_array::<4>("9D96C13C"));
        assert_eq!(auth_result.pd_cap2, PCDCAP2);
        assert_eq!(auth_result.pcd_cap2, PCDCAP2);
        assert_eq!(auth_result.suite.enc_ctr(), 1);
    }

    /// A corrupted `PICCResponse` must be rejected.
    #[test]
    fn verify_detects_bad_picc_response() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        let rnd_b: [u8; 16] = hex_array("56109A31977C855319CD4618C9D2AED2");
        let picc_data: [u8; 16] = hex_array("F4FC209D9D60623588B299FA5D6B2D71");
        let mut picc_response: [u8; 16] = hex_array("0125F8547D9FB8D572C90D2C2A14E235");
        picc_response[0] ^= 0x01;
        let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b);
        match verify_and_extract_auth_result::<NeverError>(
            suite,
            &rnd_a,
            &rnd_b,
            &picc_data,
            &picc_response,
        ) {
            Err(SessionError::AuthenticationMismatch) => (),
            Ok(_) => panic!("verify accepted a corrupted PICCResponse"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// Reject a mismatched `PCDCap2` echo.
    ///
    /// A PICC that echoes back a different `PCDCap2` than we sent in
    /// Part 1 must be rejected even if every MAC check passes.
    ///
    /// Builds a synthetic PICCData/PICCResponse pair with the real
    /// session keys (derived from the AN12321 handshake) but with the
    /// echoed `PCDCap2` field set to zeros instead of `02 00 00 00 00 00`.
    #[test]
    fn verify_detects_bad_pcdcap2_echo() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        let rnd_b: [u8; 16] = hex_array("56109A31977C855319CD4618C9D2AED2");

        // Forge PICCData: TI (real) || PDCap2 (zeros) || PCDCap2 (zeros,
        // should be 02 00 00 00 00 00). Then encrypt at EncCtr=0 with the
        // real SesAuthENCKey so it would decrypt back cleanly.
        let mut forge = LrpSuite::derive(&key, &rnd_a, &rnd_b);
        let mut plain = [0u8; 16];
        plain[..4].copy_from_slice(&hex_array::<4>("58EE9424"));
        // plain[4..16] = zeros (wrong PCDCap2 echo in plain[10..16]).
        forge.encrypt(Direction::Response, &[0; 4], 0, &mut plain);
        let picc_data = plain;

        // Matching MAC over RndB || RndA || PICCData with real MAC key.
        let mut mac_input = [0u8; 48];
        mac_input[..16].copy_from_slice(&rnd_b);
        mac_input[16..32].copy_from_slice(&rnd_a);
        mac_input[32..].copy_from_slice(&picc_data);
        let picc_response = forge.mac_full(&mac_input);

        let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b);
        match verify_and_extract_auth_result::<NeverError>(
            suite,
            &rnd_a,
            &rnd_b,
            &picc_data,
            &picc_response,
        ) {
            Err(SessionError::AuthenticationMismatch) => (),
            Ok(auth_result) => {
                panic!(
                    "verify accepted wrong PCDCap2 echo, got TI={:x?}",
                    auth_result.ti
                )
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}
