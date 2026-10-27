// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use zeroize::{Zeroize, Zeroizing};

use crate::Transport;
use crate::commands::authenticate::AuthResult;
use crate::crypto::ct_eq_16;
use crate::crypto::suite::{AesSuite, SessionSuite, aes_cbc_decrypt_n, aes_cbc_encrypt_n};
use crate::session::SessionError;
use crate::types::{KeyNumber, ResponseCode, ResponseStatus};

/// Copy `enc` into a `Zeroizing` buffer and decrypt with a zero IV.
fn aes_decrypt<const N: usize>(key: &[u8; 16], enc: &[u8; N]) -> Zeroizing<[u8; N]>
where
    [u8; N]: Zeroize,
{
    let mut buf = Zeroizing::new(*enc);
    aes_cbc_decrypt_n(key, &[0u8; 16], &mut buf);
    buf
}

/// `AuthenticateEV2NonFirst` for AES secure messaging (NT4H2421Gx §9.1.6,
/// §10.4.2).
///
/// Re-authenticates within an already-active AES session, deriving fresh
/// session keys (`SesAuthMACKey`, `SesAuthENCKey`) while the PICC preserves
/// TI and `CmdCtr` (p. 25–26). The caller is responsible for preserving those
/// values from the prior session and updating the [`Session`] accordingly.
///
/// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy so this
/// method stays deterministic in tests.
pub(crate) async fn authenticate_ev2_non_first<T: Transport>(
    transport: &mut T,
    key_no: KeyNumber,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<AesSuite, SessionError<T::Error>> {
    // Part 1: CLA=90 CMD=77 P1=00 P2=00 Lc=01 [KeyNo] Le=00.
    // INS=77h (NonFirst); no LenCap/PCDcap2 (§10.4.2, Table 31, p. 49).
    let part1_apdu = [0x90, 0x77, 0x00, 0x00, 0x01, key_no.as_byte(), 0x00];
    let r1 = transport.transmit(&part1_apdu).await?;
    let code = ResponseCode::desfire(r1.sw1, r1.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let rnd_b_enc: [u8; 16] =
        r1.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r1.data.as_ref().len(),
                expected: 16,
            })?;

    // Decrypt RndB (§9.1.4: IV is all zero during authentication).
    let rnd_b = aes_decrypt(key, &rnd_b_enc);

    let part2_apdu = build_part2_apdu(key, &rnd_a, &rnd_b);
    let r2 = transport.transmit(&part2_apdu).await?;
    let code = ResponseCode::desfire(r2.sw1, r2.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    // Response is only 16 bytes - no TI or cap fields (p. 26: "TI is not
    // reset and not exchanged").
    let resp_enc: [u8; 16] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
                expected: 16,
            })?;

    finish_auth_non_first(key, &rnd_a, &rnd_b, &resp_enc)
}

/// `AuthenticateEV2First` for AES secure messaging (NT4H2421Gx §9.1.5,
/// §10.4.1).
///
/// Drives the two-part challenge/response handshake with the PICC using
/// the application key `key` at slot `key_no` and the caller-supplied
/// 16-byte random `rnd_a`. On success, returns the derived [`AesSuite`]
/// session and the 4-byte Transaction Identifier chosen by the PICC.
///
/// The caller owns entropy: passing `rnd_a` in keeps this crate
/// `no_std`-clean and makes the handshake deterministically testable.
pub(crate) async fn authenticate_ev2_first<T: Transport>(
    transport: &mut T,
    key_no: KeyNumber,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<AuthResult<AesSuite>, SessionError<T::Error>> {
    // Part 1: CLA=90 CMD=71 P1=00 P2=00 Lc=05 [KeyNo LenCap=03 PCDcap2=000000] Le=00.
    // LenCap = 0x03 signals AES-128 key type and carries 3 zero bytes of PCDcap2
    // (NT4H2421Gx §10.4.1, Table 25). Both LenCap=0x00 and 0x03 work on real
    // NTAG 424 DNA hardware; 0x03 is the spec-recommended encoding.
    let part1_apdu = [
        0x90,
        0x71,
        0x00,
        0x00,
        0x05,
        key_no.as_byte(),
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    let r1 = transport.transmit(&part1_apdu).await?;
    let code = ResponseCode::desfire(r1.sw1, r1.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let rnd_b_enc: [u8; 16] =
        r1.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r1.data.as_ref().len(),
                expected: 16,
            })?;

    // Decrypt RndB (§9.1.4: IV is all zero during authentication).
    let rnd_b = aes_decrypt(key, &rnd_b_enc);

    let part2_apdu = build_part2_apdu(key, &rnd_a, &rnd_b);
    let r2 = transport.transmit(&part2_apdu).await?;
    let code = ResponseCode::desfire(r2.sw1, r2.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let resp_enc: [u8; 32] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
                expected: 32,
            })?;

    finish_auth(key, &rnd_a, &rnd_b, &resp_enc)
}

/// Build the AES authentication Part 2 APDU.
///
/// The wire form is `90 AF 00 00 20 || E(Kx, RndA || RndB') || 00`.
/// `RndB'` is `RndB` rotated left by one byte (§9.1.5).
fn build_part2_apdu(key: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 38] {
    let mut ct = [0u8; 32];
    ct[..16].copy_from_slice(rnd_a);
    ct[16..31].copy_from_slice(&rnd_b[1..]);
    ct[31] = rnd_b[0];
    aes_cbc_encrypt_n(key, &[0u8; 16], &mut ct);

    let mut apdu = [0u8; 38];
    apdu[0] = 0x90;
    apdu[1] = 0xAF;
    apdu[4] = 0x20;
    apdu[5..37].copy_from_slice(&ct);
    apdu
}

/// Decrypt the Part 2 response and derive the session suite.
///
/// Verifies `RndA'` matches the `RndA` the PCD sent (rotated left by one),
/// then derives [`AesSuite`] per §9.1.7 and returns it alongside the
/// Transaction Identifier chosen by the PICC.
fn finish_auth<E: core::error::Error + core::fmt::Debug>(
    key: &[u8; 16],
    rnd_a: &[u8; 16],
    rnd_b: &[u8; 16],
    enc: &[u8; 32],
) -> Result<AuthResult<AesSuite>, SessionError<E>> {
    let resp = aes_decrypt(key, enc);

    // Layout: TI (4) || RndA' (16) || PDcap2 (6) || PCDcap2 (6).
    let mut ti = [0u8; 4];
    ti.copy_from_slice(&resp[0..4]);
    let rnd_a_prime = &resp[4..20];

    // Rotate right by one to recover RndA; must equal what we sent.
    let mut rnd_a_received: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
    rnd_a_received[0] = rnd_a_prime[15];
    rnd_a_received[1..].copy_from_slice(&rnd_a_prime[..15]);
    if !ct_eq_16(&rnd_a_received, rnd_a) {
        return Err(SessionError::AuthenticationMismatch);
    }

    let mut pd_cap2 = [0u8; 6];
    pd_cap2.copy_from_slice(&resp[20..26]);

    let mut pcd_cap2 = [0u8; 6];
    pcd_cap2.copy_from_slice(&resp[26..32]);

    Ok(AuthResult {
        suite: AesSuite::derive(key, rnd_a, rnd_b),
        ti,
        pd_cap2,
        pcd_cap2,
    })
}

/// Verify the 16-byte NonFirst Part 2 response and derive the new session suite.
///
/// The response carries only `E(Kx, RndA')` - no TI, no cap fields (§10.4.2,
/// Table 34–35, p. 50). Verifies `rotate_right(RndA', 1) == RndA`, then
/// derives the new [`AesSuite`] via the same KDF as First (§9.1.7).
fn finish_auth_non_first<E: core::error::Error + core::fmt::Debug>(
    key: &[u8; 16],
    rnd_a: &[u8; 16],
    rnd_b: &[u8; 16],
    enc: &[u8; 16],
) -> Result<AesSuite, SessionError<E>> {
    let plain = aes_decrypt(key, enc);

    // Rotate right by one to recover RndA; must equal what we sent.
    let mut rnd_a_received: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
    rnd_a_received[0] = plain[15];
    rnd_a_received[1..].copy_from_slice(&plain[..15]);
    if !ct_eq_16(&rnd_a_received, rnd_a) {
        return Err(SessionError::AuthenticationMismatch);
    }

    Ok(AesSuite::derive(key, rnd_a, rnd_b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::aes_cbc_decrypt;
    use crate::testing::hex_array;

    #[derive(Debug)]
    struct NeverError;
    impl core::fmt::Display for NeverError {
        fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Ok(())
        }
    }
    impl core::error::Error for NeverError {}

    /// AN12196 §6.10 - `AuthenticateEV2First` with key 0x03 (all-zero default
    /// value). Verifies the Part 2 APDU bytes and TI extraction.
    #[test]
    fn part2_apdu_and_finish_an12196_key3() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("B98F4C50CF1C2E084FD150E33992B048");
        let rnd_b_enc: [u8; 16] = hex_array("B875CEB0E66A6C5CD00898DC371F92D1");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100"
            ),
        );

        let resp_enc: [u8; 32] =
            hex_array("0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A");
        let auth_result = match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Ok(v) => v,
            Err(e) => panic!("finish_auth rejected a valid transcript: {e:?}"),
        };
        assert_eq!(auth_result.ti, hex_array::<4>("7614281A"));
        assert_eq!(auth_result.pd_cap2, [0; 6]);
        assert_eq!(auth_result.pcd_cap2, [0; 6]);
        // The full KDF is pinned by `crypto::suite::tests::aes_session_keys_an12196`.
    }

    /// AN12196 §6.6 - `AuthenticateEV2First` with key 0x00.
    #[test]
    fn part2_apdu_and_finish_an12196_key0() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b_enc: [u8; 16] = hex_array("A04C124213C186F22399D33AC2A30215");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00"
            ),
        );

        let resp_enc: [u8; 32] =
            hex_array("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663");
        let auth_result = match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Ok(v) => v,
            Err(e) => panic!("finish_auth rejected a valid transcript: {e:?}"),
        };
        assert_eq!(auth_result.ti, hex_array::<4>("9D00C4DF"));
        assert_eq!(auth_result.pd_cap2, [0; 6]);
        assert_eq!(auth_result.pcd_cap2, [0; 6]);
    }

    /// A corrupted `RndA'` in the Part 2 response must be rejected.
    #[test]
    fn finish_auth_detects_wrong_rnd_a() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b_enc: [u8; 16] = hex_array("A04C124213C186F22399D33AC2A30215");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();

        // Flip one byte - any single-bit change propagates to the recovered RndA.
        let mut resp_enc: [u8; 32] =
            hex_array("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663");
        resp_enc[20] ^= 0x01;
        match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Err(SessionError::AuthenticationMismatch) => (),
            Ok(_) => panic!("finish_auth accepted a corrupted transcript"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// AN12196 §5.14, Table 23 (p. 36) - `AuthenticateEV2NonFirst` with key
    /// 0x00 (all-zero). Verifies the Part 2 APDU bytes, RndA' check, and
    /// derived session keys.
    #[test]
    fn non_first_finish_auth_an12196_table23() {
        let key = [0u8; 16];
        // From Table 23: RndB decrypted from R-APDU1.
        let rnd_b_enc: [u8; 16] = hex_array("A6A2B3C572D06C097BB8DB70463E22DC");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();
        assert_eq!(rnd_b, hex_array("6924E8D09722659A2E7DEC68E66312B8"));

        let rnd_a: [u8; 16] = hex_array("60BE759EDA560250AC57CDDC11743CF6");

        // C-APDU2 data: E(K0, RndA || RndB') - the 32-byte ciphertext from Table 23.
        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF000020BE7D45753F2CAB85F34BC60CE58B940763FE969658A532DF6D95EA2773F6E99100"
            ),
        );

        // R-APDU2: E(K0, RndA') [16 bytes].
        let resp_enc: [u8; 16] = hex_array("B888349C24B315EAB5B589E279C8263E");
        let suite = finish_auth_non_first::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc)
            .expect("valid transcript should verify");

        // Session keys from Table 23.
        let (enc_key, mac_key) = suite.session_keys();
        assert_eq!(enc_key, hex_array("4CF3CB41A22583A61E89B158D252FC53"));
        assert_eq!(mac_key, hex_array("5529860B2FC5FB6154B7F28361D30BF9"));
    }

    /// Real NTAG 424 DNA hardware - `AuthenticateEV2First` with Key 0
    /// (all-zero factory default). Verifies the Part 2 APDU bytes and
    /// TI extraction against an actual on-wire transcript.
    #[test]
    fn part2_apdu_and_finish_auth_hw_key0() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("A5F7C97067CC7C6B0C373F15028021EE");
        let rnd_b_enc: [u8; 16] = hex_array("457B8458856FA7D114513E5A65A37405");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF000020BD8315EF8B1AFF79FB51287D1E93DCE49EE4EC2EEFD5285A499B9EDC5921992200"
            ),
        );

        let resp_enc: [u8; 32] =
            hex_array("94A3D20D1035D7FF691B611360578F7765EC56EC456739A4533FDBA50F9CDFBB");
        let auth_result = match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Ok(v) => v,
            Err(e) => panic!("finish_auth rejected a valid hardware transcript: {e:?}"),
        };
        assert_eq!(auth_result.ti, hex_array::<4>("704B5F99"));
        assert_eq!(auth_result.pd_cap2, [0; 6]);
        assert_eq!(auth_result.pcd_cap2, [0; 6]);
    }

    /// Real NTAG 424 DNA hardware - `AuthenticateEV2NonFirst` with Key 0
    /// (all-zero factory default). Verifies the Part 2 APDU bytes,
    /// RndA' verification, and derived session keys against an actual
    /// on-wire transcript.
    #[test]
    fn non_first_finish_auth_hw_key0() {
        let key = [0u8; 16];
        let rnd_b_enc: [u8; 16] = hex_array("01E9CB96C9EE3873B4135A6E08DED325");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();

        let rnd_a: [u8; 16] = hex_array("1AC618A15F5CB19BF10E5F649DC98764");

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex_array::<38>(
                "90AF00002075577A7FFEA719AE781951B1F9298FC947FA5A0AE2BC99CCF11A89C88D27709B00"
            ),
        );

        let resp_enc: [u8; 16] = hex_array("2E54DF5D25A366C03DF7A07F4B85301C");
        let _suite = finish_auth_non_first::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc)
            .expect("valid hardware transcript should verify");
    }

    /// A corrupted 16-byte NonFirst Part 2 response must be rejected.
    #[test]
    fn non_first_finish_auth_detects_wrong_rnd_a() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("60BE759EDA560250AC57CDDC11743CF6");
        let rnd_b: [u8; 16] = hex_array("6924E8D09722659A2E7DEC68E66312B8");
        let mut resp_enc: [u8; 16] = hex_array("B888349C24B315EAB5B589E279C8263E");
        resp_enc[0] ^= 0x01;
        match finish_auth_non_first::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Err(SessionError::AuthenticationMismatch) => (),
            Ok(_) => panic!("non_first finish_auth accepted a corrupted transcript"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}
