// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Secure Messaging cipher suites for NT4H2421Gx (NTAG 424 DNA).
//!
//! The chip supports two Secure Messaging modes that share protocol framing
//! but differ in their cryptographic primitive (NT4H2421Gx §9):
//!
//! - **AES Secure Messaging** (§9.1) - AES-128 CMAC for integrity, AES-128
//!   CBC for confidentiality. The CBC IV is rebuilt from `(TI, CmdCtr)` on
//!   every message.
//! - **LRP Secure Messaging** (§9.2) - Leakage Resilient Primitive (NXP
//!   AN12304) in place of AES. `CMAC_LRP` for integrity, `LRICB` for
//!   confidentiality with a stateful 32-bit `EncCtr` that persists across
//!   messages.
//!
//! The [`SessionSuite`] trait abstracts over both modes so the session
//! layer can drive either one through a single code path. Concrete impls
//! are [`AesSuite`] and [`LrpSuite`].

use aes::{
    Aes128,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use cmac::{Cmac, Mac, digest::InnerInit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::file_settings::CryptoMode;

use super::lrp::{Block, Lrp, generate_plaintexts, generate_updated_keys};

/// Direction of an encrypted message.
///
/// Selects the 2-byte label that separates command IVs from response
/// IVs (§9.1.4 / §9.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// PCD → PICC. Label `A5 5A`.
    Command,
    /// PICC → PCD. Label `5A A5`.
    Response,
}

impl Direction {
    const fn label(self) -> [u8; 2] {
        match self {
            Self::Command => [0xA5, 0x5A],
            Self::Response => [0x5A, 0xA5],
        }
    }
}

/// Post-authentication cipher suite driving NT4H2421Gx Secure Messaging.
///
/// Implemented for AES (§9.1) and LRP (§9.2). A suite owns
/// the session keys `SesAuthMACKey` / `SesAuthENCKey` plus any mode-specific
/// state - most notably the 32-bit LRP `EncCtr` that persists across
/// messages (§9.2.4). AES has no such counter: its CBC IV is rebuilt from
/// scratch on every call.
///
/// Protocol state that is **not** owned by the suite and must be supplied
/// per call:
///
/// - `ti: [u8; 4]` - Transaction Identifier (§9.1.1), set once by the
///   handshake and constant for the rest of the session.
/// - `cmd_ctr: u16` - Command Counter (§9.1.2), incremented by the caller
///   between command and response.
///
/// Both of these belong to the secure-messaging framing layer rather than
/// to the cipher itself, which is why they are arguments and not fields.
/// The AES suite consumes them during IV derivation; the LRP suite ignores
/// them in `encrypt`/`decrypt` because LRP's IV is the stateful `EncCtr`.
pub trait SessionSuite: Sized {
    const MODE: CryptoMode;

    /// Derive session keys from the authentication transcript.
    ///
    /// Uses the static application key `kx` and the 16-byte randoms
    /// `rnd_a` (PCD) and `rnd_b` (PICC) exchanged during the handshake.
    ///
    /// - AES (§9.1.7): two CMAC-AES derivations of `SV1` / `SV2` keyed by
    ///   `kx` produce `SesAuthENCKey` and `SesAuthMACKey`.
    /// - LRP (§9.2.7): one `CMAC_LRP` of `SV` under `kx` yields the
    ///   `SesAuthMasterKey`; the two session LRP instances are built from
    ///   that master key's plaintext table together with `UK[0]` (MAC) and
    ///   `UK[1]` (ENC).
    fn derive(kx: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> Self;

    /// Compute the truncated session MAC.
    ///
    /// This is a CMAC over `data` with the session MAC key, truncated to
    /// 8 bytes by keeping the even-numbered (1-indexed) output bytes in
    /// MSB-first order (§9.1.3 / §9.2.3).
    ///
    /// The caller assembles the full NTAG 424 DNA MAC input, e.g.
    /// `Cmd || CmdCtr || TI || CmdHeader || CmdData` for commands and
    /// `RC  || CmdCtr || TI || RespData` for responses (§9.1.9).
    fn mac(&self, data: &[u8]) -> [u8; 8];

    /// Encrypt `buf` in place with the session ENC key.
    ///
    /// `buf.len()` must be a positive multiple of 16. Both modes use
    /// ISO/IEC 9797-1 Method 2 padding - applying it is the caller's
    /// responsibility, since the padding rule is identical across suites.
    ///
    /// Returns `None` if `buf.len()` is not a positive multiple of 16.
    ///
    /// The AES suite rebuilds the CBC IV from `(dir, ti, cmd_ctr)` on
    /// every call (§9.1.4). The LRP suite ignores those three arguments
    /// and uses its internal `EncCtr`, advancing it by one per 16-byte
    /// block processed (§9.2.4).
    fn encrypt(&mut self, dir: Direction, ti: &[u8; 4], cmd_ctr: u16, buf: &mut [u8])
    -> Option<()>;

    /// In-place inverse of [`encrypt`](Self::encrypt). Same length and
    /// state rules apply. Returns `None` if `buf.len()` is not a
    /// positive multiple of 16.
    fn decrypt(&mut self, dir: Direction, ti: &[u8; 4], cmd_ctr: u16, buf: &mut [u8])
    -> Option<()>;
}

/// Truncate a 16-byte CMAC output.
///
/// Per §9.1.3 / §9.2.3, keep the even-numbered (1-indexed) bytes in
/// MSB-first order: 0-based indices 1, 3, 5, 7, 9, 11, 13, 15.
pub(crate) fn truncate_mac(full: &[u8; 16]) -> [u8; 8] {
    core::array::from_fn(|i| full[2 * i + 1])
}

/// Assemble the 32-byte AES session-key input vector `SV1` / `SV2`
/// (§9.1.7). `label` selects between the two (A5 5A for ENC, 5A A5 for
/// MAC).
fn session_vector_aes(label: [u8; 2], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 32] {
    let mut sv = [0u8; 32];
    sv[0..2].copy_from_slice(&label);
    sv[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    sv[6..8].copy_from_slice(&rnd_a[0..2]);
    for i in 0..6 {
        sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i];
    }
    sv[14..24].copy_from_slice(&rnd_b[6..16]);
    sv[24..32].copy_from_slice(&rnd_a[8..16]);
    sv
}

/// Assemble the 32-byte LRP session-key input vector `SV` (§9.2.7). The
/// label is fixed (`96 69`) and appears as a suffix rather than a prefix.
fn session_vector_lrp(rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 32] {
    let mut sv = [0u8; 32];
    sv[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    sv[4..6].copy_from_slice(&rnd_a[0..2]);
    for i in 0..6 {
        sv[6 + i] = rnd_a[2 + i] ^ rnd_b[i];
    }
    sv[12..22].copy_from_slice(&rnd_b[6..16]);
    sv[22..30].copy_from_slice(&rnd_a[8..16]);
    sv[30..32].copy_from_slice(&[0x96, 0x69]);
    sv
}

pub(crate) fn cmac_aes(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("16-byte AES key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn cmac_lrp(lrp: Lrp, data: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Lrp>::inner_init(lrp);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ---------------------------------------------------------------------------
// AES suite
// ---------------------------------------------------------------------------

/// AES-128 Secure Messaging suite (§9.1). Stateless between messages: the
/// CBC IV is a deterministic function of `(dir, ti, cmd_ctr)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesSuite {
    mac_key: [u8; 16],
    enc_key: [u8; 16],
}

impl AesSuite {
    /// Construct directly from known session keys. Intended for test
    /// harnesses that replay AN12196 vectors without a handshake; real
    /// code should use [`Self::derive`].
    #[cfg(test)]
    pub(crate) fn from_keys(enc_key: [u8; 16], mac_key: [u8; 16]) -> Self {
        Self { enc_key, mac_key }
    }

    /// Return `(enc_key, mac_key)` for test assertions.
    #[cfg(test)]
    pub(crate) fn session_keys(&self) -> ([u8; 16], [u8; 16]) {
        (self.enc_key, self.mac_key)
    }

    /// `IV = E(SesAuthENCKey, label || TI || CmdCtr(LSB) || 0…0)` per
    /// §9.1.4. `label` is `A5 5A` for commands, `5A A5` for responses.
    fn iv(&self, dir: Direction, ti: &[u8; 4], cmd_ctr: u16) -> [u8; 16] {
        let mut input = [0u8; 16];
        input[0..2].copy_from_slice(&dir.label());
        input[2..6].copy_from_slice(ti);
        input[6..8].copy_from_slice(&cmd_ctr.to_le_bytes());
        let cipher = Aes128::new(&Array::from(self.enc_key));
        let mut iv = Block::default();
        cipher.encrypt_block_b2b(&Array::from(input), &mut iv);
        iv.into()
    }
}

impl SessionSuite for AesSuite {
    const MODE: CryptoMode = CryptoMode::Aes;

    fn derive(kx: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> Self {
        let sv1 = session_vector_aes([0xA5, 0x5A], rnd_a, rnd_b);
        let sv2 = session_vector_aes([0x5A, 0xA5], rnd_a, rnd_b);
        Self {
            enc_key: cmac_aes(kx, &sv1),
            mac_key: cmac_aes(kx, &sv2),
        }
    }

    fn mac(&self, data: &[u8]) -> [u8; 8] {
        truncate_mac(&cmac_aes(&self.mac_key, data))
    }

    fn encrypt(
        &mut self,
        dir: Direction,
        ti: &[u8; 4],
        cmd_ctr: u16,
        buf: &mut [u8],
    ) -> Option<()> {
        aes_cbc_encrypt(&self.enc_key, &self.iv(dir, ti, cmd_ctr), buf)
    }

    fn decrypt(
        &mut self,
        dir: Direction,
        ti: &[u8; 4],
        cmd_ctr: u16,
        buf: &mut [u8],
    ) -> Option<()> {
        aes_cbc_decrypt(&self.enc_key, &self.iv(dir, ti, cmd_ctr), buf)
    }
}

/// AES-128 CBC encryption in place. No padding is applied.
///
/// Returns `None` if `buf.len()` is not a positive multiple of 16.
///
/// Shared between the §9.1.4 session-message path (IV derived from
/// `TI || CmdCtr`) and the §9.1.5 authentication handshake (zero IV,
/// no padding).
#[must_use]
pub(crate) fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) -> Option<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(16) {
        return None;
    }
    let cipher = Aes128::new(&Array::from(*key));
    let mut prev: [u8; 16] = *iv;
    for chunk in buf.as_chunks_mut::<16>().0 {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let mut block = Block::default();
        block.copy_from_slice(chunk);
        let mut out = Block::default();
        cipher.encrypt_block_b2b(&block, &mut out);
        chunk.copy_from_slice(&out);
        prev.copy_from_slice(chunk);
    }
    Some(())
}

/// In-place inverse of [`aes_cbc_encrypt`]. Same length preconditions.
/// Returns `None` if `buf.len()` is not a positive multiple of 16.
#[must_use]
pub(crate) fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) -> Option<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(16) {
        return None;
    }
    let cipher = Aes128::new(&Array::from(*key));
    let mut prev: [u8; 16] = *iv;
    let mut save = [0u8; 16];
    for chunk in buf.as_chunks_mut::<16>().0 {
        save.copy_from_slice(chunk);
        let mut block = Block::default();
        block.copy_from_slice(chunk);
        let mut out = Block::default();
        cipher.decrypt_block_b2b(&block, &mut out);
        chunk.copy_from_slice(&out);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev.copy_from_slice(&save);
    }
    Some(())
}

/// Length-typed companion to [`aes_cbc_encrypt`].
///
/// Const-asserts that `N` is a positive multiple of 16, so calling with a
/// wrong-sized buffer is a compile error rather than a runtime `None`.
pub(crate) fn aes_cbc_encrypt_n<const N: usize>(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8; N]) {
    const {
        assert!(
            N > 0 && N.is_multiple_of(16),
            "AES-CBC buffer length must be a positive multiple of 16",
        );
    }
    aes_cbc_encrypt(key, iv, buf).expect("const-asserted length");
}

/// Length-typed companion to [`aes_cbc_decrypt`]. Same compile-time
/// length guarantee as [`aes_cbc_encrypt_n`].
pub(crate) fn aes_cbc_decrypt_n<const N: usize>(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8; N]) {
    const {
        assert!(
            N > 0 && N.is_multiple_of(16),
            "AES-CBC buffer length must be a positive multiple of 16",
        );
    }
    aes_cbc_decrypt(key, iv, buf).expect("const-asserted length");
}

// ---------------------------------------------------------------------------
// LRP suite
// ---------------------------------------------------------------------------

/// LRP Secure Messaging suite (§9.2), built on the AN12304 LRP primitive
/// in [`crate::crypto::lrp`].
///
/// Holds the two session LRP instances and the persistent 32-bit `EncCtr`
/// that advances by one per 16-byte block encrypted or decrypted (§9.2.4).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LrpSuite {
    mac_key: Lrp,
    enc_key: Lrp,
    /// `EncCtr` per §9.2.4 - 32-bit unsigned integer, MSB-first on the
    /// wire. Reset to zero by [`Self::derive`] and advanced in place by
    /// [`Self::encrypt`] / [`Self::decrypt`].
    enc_ctr: u32,
}

impl LrpSuite {
    /// Current value of `EncCtr`. Advances by one per 16-byte block
    /// processed by [`Self::encrypt`] / [`Self::decrypt`].
    pub fn enc_ctr(&self) -> u32 {
        self.enc_ctr
    }

    /// Set `EncCtr` to a specific value and return `self`. Used in
    /// tests that construct a mid-session suite without replaying the
    /// full authentication handshake. For example, `AuthenticateLRPFirst`
    /// decrypts one block during the handshake, so any test that uses the
    /// resulting session must start with `enc_ctr = 1`.
    #[cfg(test)]
    pub(crate) fn with_enc_ctr(mut self, enc_ctr: u32) -> Self {
        self.enc_ctr = enc_ctr;
        self
    }

    /// Full (untruncated) 16-byte `CMAC_LRP` over `data` with the session MAC
    /// key (§9.2.3). Used during the `AuthenticateLRPFirst` handshake where
    /// `PCDResponse` and `PICCResponse` are full-length MACs rather than the
    /// 8-byte truncated `MACt` used in secure-messaging commands.
    pub(crate) fn mac_full(&self, data: &[u8]) -> [u8; 16] {
        cmac_lrp(self.mac_key.clone(), data)
    }
}

impl SessionSuite for LrpSuite {
    const MODE: CryptoMode = CryptoMode::Lrp;

    fn derive(kx: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> Self {
        // SesAuthMasterKey = CMAC_LRP(Kx, SV), untruncated.
        let kx_lrp = Lrp::from_base_key(*kx);
        let sv = session_vector_lrp(rnd_a, rnd_b);
        let master = cmac_lrp(kx_lrp, &sv);

        // SesAuthSPT = plaintexts(SesAuthMasterKey);
        // SesAuthMACUpdateKey = UK[0], SesAuthENCUpdateKey = UK[1].
        let plaintexts = generate_plaintexts(master);
        let [uk_mac, uk_enc] = generate_updated_keys::<2>(master);

        Self {
            mac_key: Lrp::from_parts(plaintexts, uk_mac),
            enc_key: Lrp::from_parts(plaintexts, uk_enc),
            enc_ctr: 0,
        }
    }

    fn mac(&self, data: &[u8]) -> [u8; 8] {
        truncate_mac(&cmac_lrp(self.mac_key.clone(), data))
    }

    fn encrypt(
        &mut self,
        _dir: Direction,
        _ti: &[u8; 4],
        _cmd_ctr: u16,
        buf: &mut [u8],
    ) -> Option<()> {
        let mut ctr = self.enc_ctr.to_be_bytes();
        self.enc_key.lricb_encrypt_in_place(&mut ctr, buf)?;
        self.enc_ctr = u32::from_be_bytes(ctr);
        Some(())
    }

    fn decrypt(
        &mut self,
        _dir: Direction,
        _ti: &[u8; 4],
        _cmd_ctr: u16,
        buf: &mut [u8],
    ) -> Option<()> {
        let mut ctr = self.enc_ctr.to_be_bytes();
        self.enc_key.lricb_decrypt_in_place(&mut ctr, buf)?;
        self.enc_ctr = u32::from_be_bytes(ctr);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hex_array, hex_bytes};
    use alloc::vec::Vec;

    #[test]
    fn aes_cbc_encrypt_rejects_empty_buffer() {
        assert_eq!(aes_cbc_encrypt(&[0u8; 16], &[0u8; 16], &mut []), None);
    }

    #[test]
    fn aes_cbc_decrypt_rejects_non_block_buffer() {
        let mut buf = [0u8; 15];
        assert_eq!(aes_cbc_decrypt(&[0u8; 16], &[0u8; 16], &mut buf), None);
    }

    // AN12196 §5.10 "AuthenticateEV2First with key 0x03". Worked example
    // with Kx = all zeros, RndA / RndB from the transcript, and the
    // resulting SV1/SV2 and session keys explicitly tabulated (steps
    // 25-28). Validates `session_vector_aes` and `AesSuite::derive`.
    #[test]
    fn aes_session_keys_an12196() {
        let kx = [0u8; 16];
        let rnd_a = hex_array("B98F4C50CF1C2E084FD150E33992B048");
        let rnd_b = hex_array("91517975190DCEA6104948EFA3085C1B");

        let sv1 = session_vector_aes([0xA5, 0x5A], &rnd_a, &rnd_b);
        let sv2 = session_vector_aes([0x5A, 0xA5], &rnd_a, &rnd_b);
        assert_eq!(
            sv1,
            hex_array("A55A00010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048"),
        );
        assert_eq!(
            sv2,
            hex_array("5AA500010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048"),
        );

        let suite = AesSuite::derive(&kx, &rnd_a, &rnd_b);
        assert_eq!(suite.enc_key, hex_array("7A93D6571E4B180FCA6AC90C9A7488D4"));
        assert_eq!(suite.mac_key, hex_array("FC4AF159B62E549B5812394CAB1918CC"));
    }

    // AN12196 §5.6 "AuthenticateEV2First with key 0x00". Separate worked
    // example from the key-0x03 case above, useful as an independent AES
    // KDF vector with different RndA / RndB / TI / session keys.
    #[test]
    fn aes_session_keys_key0_an12196() {
        let kx = [0u8; 16];
        let rnd_a = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b = hex_array("B9E2FC789B64BF237CCCAA20EC7E6E48");

        let sv1 = session_vector_aes([0xA5, 0x5A], &rnd_a, &rnd_b);
        let sv2 = session_vector_aes([0x5A, 0xA5], &rnd_a, &rnd_b);
        assert_eq!(
            sv1,
            hex_array("A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F"),
        );
        assert_eq!(
            sv2,
            hex_array("5AA50001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F"),
        );

        let suite = AesSuite::derive(&kx, &rnd_a, &rnd_b);
        assert_eq!(suite.enc_key, hex_array("1309C877509E5A215007FF0ED19CA564"));
        assert_eq!(suite.mac_key, hex_array("4C6626F5E72EA694202139295C7A7FC7"));
    }

    // AN12196 §5.12 "Write to Proprietary File - using Cmd.WriteData,
    // CommMode.FULL". The worked example tabulates the AES session keys,
    // IV derivation, CBC ciphertext, full CMAC, truncated MAC, and the
    // response MAC check. Validates the AES secure-messaging behavior
    // implemented by `AesSuite`.
    #[test]
    fn aes_secure_messaging_write_data_an12196() {
        let mut suite = AesSuite {
            enc_key: hex_array("7A93D6571E4B180FCA6AC90C9A7488D4"),
            mac_key: hex_array("FC4AF159B62E549B5812394CAB1918CC"),
        };
        let ti = [0x76, 0x14, 0x28, 0x1A];
        let cmd_ctr = 0u16;

        let iv = suite.iv(Direction::Command, &ti, cmd_ctr);
        assert_eq!(iv, hex_array("4C651A64261A90307B6C293F611C7F7B"));

        let mut enc = hex_bytes("0102030405060708090A800000000000");
        suite
            .encrypt(Direction::Command, &ti, cmd_ctr, &mut enc)
            .unwrap();
        assert_eq!(enc, hex_bytes("6B5E6804909962FC4E3FF5522CF0F843"));

        let mac_input = hex_bytes("8D00007614281A030000000A00006B5E6804909962FC4E3FF5522CF0F843");
        assert_eq!(
            cmac_aes(&suite.mac_key, &mac_input),
            hex_array("426CD70CE153ED315E5B139CB97384AA")
        );
        assert_eq!(suite.mac(&mac_input), hex_array("6C0C53315B9C73AA"));

        let resp_mac_input = hex_bytes("0001007614281A");
        assert_eq!(
            cmac_aes(&suite.mac_key, &resp_mac_input),
            hex_array("86C2486D35237F6E974A437C4004C46D"),
        );
        assert_eq!(suite.mac(&resp_mac_input), hex_array("C26D236E4A7C046D"));
    }

    // AN12196 §5.4 "Get File Settings". This is a compact CommMode.MAC
    // example that validates the raw AES CMAC and the NTAG MACt truncation.
    #[test]
    fn aes_mac_mode_get_file_settings_an12196() {
        let suite = AesSuite {
            enc_key: [0u8; 16],
            mac_key: hex_array("8248134A386E86EB7FAF54A52E536CB6"),
        };
        let mac_input = hex_bytes("F500007A21085E02");
        assert_eq!(
            cmac_aes(&suite.mac_key, &mac_input),
            hex_array("B565AC978FA46D5784C845CD1444102C"),
        );
        assert_eq!(suite.mac(&mac_input), hex_array("6597A457C8CD442C"));
    }

    // AN12196 §5.8.2 "Write NDEF File - using Cmd.WriteData, CommMode.FULL".
    // This is the clean multi-block AES secure-messaging vector in the note:
    // the published IV and ciphertext decrypt to a 9-block padded plaintext,
    // which we can then re-encrypt to validate CBC chaining in both
    // directions.
    #[test]
    fn aes_secure_messaging_write_ndef_multiblock_an12196() {
        let mut suite = AesSuite {
            enc_key: hex_array("1309C877509E5A215007FF0ED19CA564"),
            mac_key: hex_array("4C6626F5E72EA694202139295C7A7FC7"),
        };
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let cmd_ctr = 0u16;

        let iv = suite.iv(Direction::Command, &ti, cmd_ctr);
        assert_eq!(iv, hex_array("D2CB7277A17841A06654A48188C1F8F5"));

        let expected_ct = hex_bytes(
            "421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768BFE596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D651A3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802AF745660F2B4",
        );
        let expected_pt = hex_bytes(
            "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D3030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000",
        );

        let mut pt = expected_pt.clone();
        suite
            .encrypt(Direction::Command, &ti, cmd_ctr, &mut pt)
            .unwrap();
        assert_eq!(pt, expected_ct);

        let mut ct = expected_ct;
        suite
            .decrypt(Direction::Command, &ti, cmd_ctr, &mut ct)
            .unwrap();
        assert_eq!(ct, expected_pt);
    }

    // AN12196 §5.20 "Get NTAG 424 DNA's UID" (Table 28). The table gives
    // a response-side AES secure-messaging example with published session
    // keys, request MAC, response ciphertext, response IV, decrypted UID,
    // and response MAC. The prose in step 13 mentions `Cmd`, but the
    // published CMAC matches `Status || CmdCtr+1 || TI || ciphertext`.
    #[test]
    fn aes_secure_messaging_get_uid_an12196() {
        let mut suite = AesSuite {
            enc_key: hex_array("2B4D963C014DC36F24F69A50A394F875"),
            mac_key: hex_array("379D32130CE61705DD5FD8C36B95D764"),
        };
        let ti = [0xDF, 0x05, 0x55, 0x22];

        let cmd_mac_input = hex_bytes("510000DF055522");
        assert_eq!(
            cmac_aes(&suite.mac_key, &cmd_mac_input),
            hex_array("CC8E8C2CD015945AFDDD7DA9B19BB9E3"),
        );
        assert_eq!(suite.mac(&cmd_mac_input), hex_array("8E2C155ADDA99BE3"));

        let response_ciphertext: [u8; 16] = hex_array("70756055688505B52A5E26E59E329CD6");
        let iv = suite.iv(Direction::Response, &ti, 1);
        assert_eq!(iv, hex_array("7F6BB0B278EA054CBD238C5D9E9E342B"));

        let mut plaintext = response_ciphertext;
        suite
            .decrypt(Direction::Response, &ti, 1, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, hex_array("04958CAA5C5E80800000000000000000"));
        assert_eq!(&plaintext[..7], &hex_bytes("04958CAA5C5E80"));

        let resp_mac_input = hex_bytes("000100DF05552270756055688505B52A5E26E59E329CD6");
        assert_eq!(
            cmac_aes(&suite.mac_key, &resp_mac_input),
            hex_array("F4593D5FAB671F225798C4EA894195B7"),
        );
        assert_eq!(suite.mac(&resp_mac_input), hex_array("595F672298EA41B7"));
    }

    // AN12321 §4 "Authentication using AuthenticateLRPFirst". Key 0x03 with
    // the default all-zero value; the transcript lists the session vector
    // (step 16) and both session update keys derived from the resulting
    // SesAuthMasterKey. Validates `session_vector_lrp` and the UK ordering
    // used by `LrpSuite::derive` (UK[0] = MAC, UK[1] = ENC).
    #[test]
    fn lrp_session_keys_an12321() {
        let kx = [0u8; 16];
        let rnd_a = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        let rnd_b = hex_array("56109A31977C855319CD4618C9D2AED2");

        let sv = session_vector_lrp(&rnd_a, &rnd_b);
        assert_eq!(
            sv,
            hex_array("0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669"),
        );

        let suite = LrpSuite::derive(&kx, &rnd_a, &rnd_b);
        let mac_uk: [u8; 16] = (*suite.mac_key.k_prime()).into();
        let enc_uk: [u8; 16] = (*suite.enc_key.k_prime()).into();
        assert_eq!(mac_uk, hex_array("F56CADE598CC2A3FE47E438CFEB885DB"));
        assert_eq!(enc_uk, hex_array("E9043D65AB21C0C422781099AB25EFDD"));
        assert_eq!(suite.enc_ctr, 0);
    }

    // AN12321 §4 "Authentication using AuthenticateLRPFirst". This is the
    // only worked example in the note that actually exercises the finalized
    // LRP session keys. It gives the MAC_LRP over `RndA || RndB`, the first
    // encrypted PICC block under `EncCtr = 0`, and the PICC response MAC
    // over `RndB || RndA || PICCData`.
    #[test]
    fn lrp_authenticate_first_exchange_an12321() {
        let kx = [0u8; 16];
        let rnd_a = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        let rnd_b = hex_array("56109A31977C855319CD4618C9D2AED2");
        let mut suite = LrpSuite::derive(&kx, &rnd_a, &rnd_b);

        let pcd_mac_input =
            hex_bytes("74D7DF6A2CEC0B72B412DE0D2B1117E656109A31977C855319CD4618C9D2AED2");
        assert_eq!(
            cmac_lrp(suite.mac_key.clone(), &pcd_mac_input),
            hex_array("189B59DCEDC31A3D3F38EF8D4810B3B4"),
        );

        let mut picc_data = hex_bytes("F4FC209D9D60623588B299FA5D6B2D71");
        suite
            .decrypt(Direction::Response, &[0; 4], 0, &mut picc_data)
            .unwrap();
        assert_eq!(picc_data, hex_bytes("58EE9424020000000000020000000000"));
        assert_eq!(suite.enc_ctr(), 1);

        let picc_mac_input = hex_bytes(
            "56109A31977C855319CD4618C9D2AED274D7DF6A2CEC0B72B412DE0D2B1117E6F4FC209D9D60623588B299FA5D6B2D71",
        );
        assert_eq!(
            cmac_lrp(suite.mac_key.clone(), &picc_mac_input),
            hex_array("0125F8547D9FB8D572C90D2C2A14E235"),
        );
    }

    // Additional stateful LRP FULL-mode sequence from `nfc-ev2-crypto`'s
    // `test_lrp_cmd`. This one is valuable because it exercises the rolling
    // `EncCtr` across several command/response exchanges after auth.
    #[test]
    fn lrp_stateful_get_uid_sequence_nfc_ev2_crypto() {
        let auth_key = [0u8; 16];
        let sv: [u8; 32] =
            hex_array("00010080993C4EED466BFC0E7EE1D30C1EBD0DEA6F6481E0D70E9A174E789669");

        let master = cmac_lrp(Lrp::from_base_key(auth_key), &sv);
        let plaintexts = generate_plaintexts(master);
        let [uk_mac, uk_enc] = generate_updated_keys::<2>(master);

        let mut suite = LrpSuite {
            mac_key: Lrp::from_parts(plaintexts, uk_mac),
            enc_key: Lrp::from_parts(plaintexts, uk_enc),
            enc_ctr: 1,
        };
        let ti = [0x4F, 0x5E, 0x84, 0x07];

        let vectors = [
            (
                0u16,
                "C37D6270F674CC6D",
                "5EC351196B8E2943DB04FCD4A952F53D",
                "A2830DC2258E4539",
            ),
            (
                1u16,
                "D65CCB81E5591400",
                "D80B735F7B4C8E7E8A3CDAAA4410F35F",
                "752769C8EBC48E1A",
            ),
            (
                2u16,
                "8C677D7DCC349371",
                "9CCD031474A50199C696D8EF272E231A",
                "10173FAF41B614E4",
            ),
        ];

        for (i, (cmd_ctr, cmd_mact, resp_ct, resp_mact)) in vectors.iter().enumerate() {
            let mut cmd_input = Vec::with_capacity(7);
            cmd_input.push(0x51);
            cmd_input.extend_from_slice(&cmd_ctr.to_le_bytes());
            cmd_input.extend_from_slice(&ti);
            assert_eq!(
                suite.mac(&cmd_input),
                hex_array(cmd_mact),
                "cmd MACt vector {i}"
            );

            let resp_ciphertext = hex_bytes(resp_ct);
            let mut resp_input = Vec::with_capacity(7 + resp_ciphertext.len());
            resp_input.push(0x00);
            resp_input.extend_from_slice(&(cmd_ctr + 1).to_le_bytes());
            resp_input.extend_from_slice(&ti);
            resp_input.extend_from_slice(&resp_ciphertext);
            assert_eq!(
                suite.mac(&resp_input),
                hex_array(resp_mact),
                "resp MACt vector {i}"
            );

            let mut pt = resp_ciphertext;
            suite
                .decrypt(Direction::Response, &ti, cmd_ctr + 1, &mut pt)
                .unwrap();
            assert_eq!(
                pt,
                hex_bytes("04940D2A2F7080800000000000000000"),
                "resp PT vector {i}"
            );
            assert_eq!(suite.enc_ctr(), i as u32 + 2, "enc_ctr vector {i}");
        }
    }

    // Direct command-path LRP encrypt/decrypt using the `test_lrp_cmd2`
    // sequence from `nfc-ev2-crypto`. This covers `LrpSuite::encrypt()` in
    // addition to the response-side decrypt path already exercised above.
    #[test]
    fn lrp_command_encrypt_decrypt_nfc_ev2_crypto() {
        let auth_key = [0u8; 16];
        let sv: [u8; 32] =
            hex_array("0001008008A6953C60BC3D34E53766689732E2A203FF23855751D644ED519669");

        let master = cmac_lrp(Lrp::from_base_key(auth_key), &sv);
        let plaintexts = generate_plaintexts(master);
        let [uk_mac, uk_enc] = generate_updated_keys::<2>(master);

        let mut suite = LrpSuite {
            mac_key: Lrp::from_parts(plaintexts, uk_mac),
            enc_key: Lrp::from_parts(plaintexts, uk_enc),
            enc_ctr: 1,
        };

        let cmd_mac_input =
            hex_bytes("8D0000204F227603000000030000EAF0FAD0430ECDC947A822E12EC8D5F3");
        assert_eq!(suite.mac(&cmd_mac_input), hex_array("BB75F218B405FDBC"));

        let padded_cmd = hex_bytes("01020380000000000000000000000000");
        let mut ct = padded_cmd.clone();
        suite
            .encrypt(Direction::Command, &[0x20, 0x4F, 0x22, 0x76], 0, &mut ct)
            .unwrap();
        assert_eq!(ct, hex_bytes("EAF0FAD0430ECDC947A822E12EC8D5F3"));
        assert_eq!(suite.enc_ctr(), 2);

        let mut fresh_suite = LrpSuite {
            mac_key: suite.mac_key.clone(),
            enc_key: suite.enc_key.clone(),
            enc_ctr: 1,
        };
        let mut pt = hex_bytes("EAF0FAD0430ECDC947A822E12EC8D5F3");
        fresh_suite
            .decrypt(Direction::Command, &[0, 0, 0, 0], 999, &mut pt)
            .unwrap();
        assert_eq!(pt, padded_cmd);
        assert_eq!(fresh_suite.enc_ctr(), 2);
    }
}
