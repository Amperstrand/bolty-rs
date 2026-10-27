// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! AES-128 key diversification.
//!
//! The methods implemented in this module allow to generate unique
//! AES-128 keys from a master key if combined with tag specific information.
//! This is useful to avoid storing multiple keys, keys can
//! be derived on the fly when needed.
//!
//! The diversification process is based on AES-CMAC and follows the
//! steps outlined in NXP's application note AN10922 §2.2. There are two main functions:
//!
//! - The [`diversify_aes128`] function takes a master key and
//!   a generic diversification input, and produces a unique AES-128 key.
//! - The [`diversify_ntag424`] function is a helper that assembles the diversification input
//!   using the recommended input for NTAG 424 DNA,
//!   which includes the tag's UID, a fixed AID, a key number,
//!   and an application-defined system identifier.
//!
//! # Example
//!
//! ```
//! use ntag424::key_diversification::diversify_aes128;
//!
//! // AN10922 §2.2.1 test vector
//! let master_key = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
//! ];
//! let uid = [0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80];
//! let aid = [0x30, 0x42, 0xF5];
//! let sys_id = b"NXP Abu";
//!
//! let mut m = Vec::new();
//! m.extend_from_slice(&uid);
//! m.extend_from_slice(&aid);
//! m.extend_from_slice(sys_id);
//!
//! let diversified = diversify_aes128(&master_key, &m);
//! assert_eq!(
//!     diversified,
//!     [0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3,
//!      0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75],
//! );
//! ```
use crate::types::KeyNumber;

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, BlockSizeUser, KeyInit},
};

type Block = Array<u8, <Aes128 as BlockSizeUser>::BlockSize>;

/// Diversification constant prepended to the CMAC input for AES-128
/// (AN10922 §2.2 step 2).
const DIV_CONST_AES128: u8 = 0x01;

/// Reduction polynomial for the CMAC subkey doubling operation over
/// GF(2^128) (NIST SP 800-38B).
const RB: u8 = 0x87;

/// NTAG 424 DNA NDEF application ISO DF name (`D2760000850101`,
/// NT4H2421Gx §8.2.2), used as the AID component in the diversification
/// input assembled by [`diversify_ntag424`].
pub const NTAG424_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// Maximum length of the system identifier passed to [`diversify_ntag424`].
///
/// The diversification input is `UID (7) + AID (7) + KeyNo (1) + SysId`,
/// which must fit in 31 bytes (AN10922 §2.2), leaving at most 16 bytes for
/// the system identifier.
pub const MAX_SYSTEM_ID_LEN: usize = 16;

/// Derive a per-card, per-key AES-128 key for NTAG 424 DNA.
///
/// Builds the diversification input as
/// `UID ‖ NTAG424_AID ‖ key_number ‖ system_identifier`
/// and feeds it to [`diversify_aes128`].
///
/// # Arguments
///
/// * `master_key` - the base AES-128 key stored in the SAM / backend.
/// * `uid` - the tag's permanent 7-byte UID (must **not** be the
///   randomised UID, which changes on every read).
/// * `key_number` - [`KeyNumber`] selecting which application key slot
///   the derived key is destined for. Including this ensures each slot
///   receives a different diversified key even from the same master.
/// * `system_identifier` - an application-defined label (up to 16 bytes)
///   that binds the key to your system.
///
/// # Panics
///
/// Panics if `system_identifier` is longer than [`MAX_SYSTEM_ID_LEN`]
/// (16 bytes). This is a programmer-controlled constant, not runtime data,
/// so a panic (rather than a `Result`) is the appropriate signal: callers
/// should not need to handle this at runtime.
///
/// # Example
///
/// Derive all five application keys from one master key:
///
/// ```
/// use ntag424::key_diversification::diversify_ntag424;
/// use ntag424::types::KeyNumber;
///
/// let master = [0u8; 16];
/// let uid = [0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80];
///
/// let keys: Vec<_> = [
///     KeyNumber::Key0, KeyNumber::Key1,
///     KeyNumber::Key2, KeyNumber::Key3, KeyNumber::Key4,
/// ]
/// .iter()
/// .map(|kn| diversify_ntag424(&master, &uid, *kn, b"myapp"))
/// .collect();
///
/// // Each key slot produces a unique diversified key.
/// for (i, a) in keys.iter().enumerate() {
///     for b in &keys[i + 1..] {
///         assert_ne!(a, b);
///     }
/// }
/// ```
pub fn diversify_ntag424(
    master_key: &[u8; 16],
    uid: &[u8; 7],
    key_number: KeyNumber,
    system_identifier: &[u8],
) -> [u8; 16] {
    assert!(
        system_identifier.len() <= MAX_SYSTEM_ID_LEN,
        "system identifier must be at most {} bytes, got {}",
        MAX_SYSTEM_ID_LEN,
        system_identifier.len(),
    );

    // M = UID (7) ‖ AID (7) ‖ KeyNo (1) ‖ SysId (0..=16)  - max 31 bytes.
    let mut m = [0u8; 31];
    let len = 7 + 7 + 1 + system_identifier.len();
    m[..7].copy_from_slice(uid);
    m[7..14].copy_from_slice(&NTAG424_AID);
    m[14] = key_number.as_byte();
    m[15..15 + system_identifier.len()].copy_from_slice(system_identifier);

    diversify_aes128(master_key, &m[..len])
}

/// Derives a diversified AES-128 key from `master_key` and
/// `diversification_input` per AN10922 §2.2.
///
/// # Arguments
///
/// * `master_key` - 16-byte AES-128 master key (K).
/// * `diversification_input` - 1 to 31 bytes of card-specific data (M).
///   For NTAG 424 DNA this is typically UID ‖ AID ‖ system identifier.
///
/// # Panics
///
/// Panics if `diversification_input` is empty or longer than 31 bytes.
/// These limits are defined by AN10922 §2.2 and are programmer-controlled
/// constants, not runtime data, so a panic (rather than a `Result`) is the
/// appropriate signal: callers should not need to handle this at runtime.
pub fn diversify_aes128(master_key: &[u8; 16], diversification_input: &[u8]) -> [u8; 16] {
    assert!(
        !diversification_input.is_empty() && diversification_input.len() <= 31,
        "diversification input must be 1–31 bytes, got {}",
        diversification_input.len(),
    );

    let cipher = Aes128::new(master_key.into());

    // CMAC subkey generation (NIST SP 800-38B §6.1):
    //   L  = CIPH_K(0^128)
    //   K1 = double(L)
    //   K2 = double(K1)
    let mut l = Block::default();
    cipher.encrypt_block(&mut l);
    let k1 = double(&l);
    let k2 = double(&k1);

    // Construct D = 0x01 ‖ M ‖ Padding  (always 32 bytes, AN10922 §2.2).
    // Padding uses ISO/IEC 9797-1 Method 2: 0x80 then 0x00 bytes.
    let mut d = [0u8; 32];
    d[0] = DIV_CONST_AES128;
    d[1..1 + diversification_input.len()].copy_from_slice(diversification_input);

    let padded = diversification_input.len() < 31;
    if padded {
        d[1 + diversification_input.len()] = 0x80;
    }

    // XOR last block with K2 (padded) or K1 (no padding) per CMAC.
    let subkey = if padded { &k2 } else { &k1 };
    for i in 0..16 {
        d[16 + i] ^= subkey[i];
    }

    // AES-CBC-MAC (IV = 0) over two 16-byte blocks.
    let mut state = Block::default();
    for i in 0..16 {
        state[i] ^= d[i];
    }
    cipher.encrypt_block(&mut state);
    for i in 0..16 {
        state[i] ^= d[16 + i];
    }
    cipher.encrypt_block(&mut state);

    state.into()
}

/// Multiply a 128-bit block by x in GF(2^128):
/// left-shift by one bit, then conditionally XOR the reduction polynomial
/// into the low byte if the high bit was set.
fn double(block: &Block) -> Block {
    let mut out = Block::default();
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    if block[0] & 0x80 != 0 {
        out[15] ^= RB;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hex_array, hex_bytes};

    /// AN10922 §2.2.1 - full AES-128 key diversification example with
    /// intermediate CMAC subkey verification.
    #[test]
    fn an10922_aes128_vector() {
        // Step 1: Master key K
        let k: [u8; 16] = hex_array("00112233445566778899AABBCCDDEEFF");

        // Verify CMAC subkey generation (steps 2–4).
        let cipher = Aes128::new((&k).into());
        let mut l = Block::default();
        cipher.encrypt_block(&mut l);
        let k0: [u8; 16] = l.into();
        assert_eq!(k0, hex_array::<16>("FDE4FBAE4A09E020EFF722969F83832B")); // Step 2: K0

        let k1 = double(&l);
        let k1_bytes: [u8; 16] = k1.into();
        assert_eq!(
            k1_bytes,
            hex_array::<16>("FBC9F75C9413C041DFEE452D3F0706D1")
        ); // Step 3: K1

        let k2 = double(&k1);
        let k2_bytes: [u8; 16] = k2.into();
        assert_eq!(
            k2_bytes,
            hex_array::<16>("F793EEB928278083BFDC8A5A7E0E0D25")
        ); // Step 4: K2

        // Steps 5–8: diversification input M = UID ‖ AID ‖ SystemIdentifier
        let m = hex_bytes("04782E21801D803042F54E585020416275");
        assert_eq!(m.len(), 17);

        // Step 15: diversified key
        let expected: [u8; 16] = hex_array("A8DD63A3B89D54B37CA802473FDA9175");
        assert_eq!(diversify_aes128(&k, &m), expected);
    }

    /// Verify that a 31-byte M (no padding) takes the K1 path.
    #[test]
    fn max_length_input_uses_k1() {
        let key = [0u8; 16];
        let m = [0xAA; 31];
        // Should not panic; exercises the K1 (unpadded) branch.
        let _ = diversify_aes128(&key, &m);
    }

    /// Verify that a 1-byte M (maximum padding) works.
    #[test]
    fn min_length_input() {
        let key = [0u8; 16];
        let m = [0x42];
        let _ = diversify_aes128(&key, &m);
    }

    #[test]
    #[should_panic(expected = "1–31 bytes")]
    fn empty_input_panics() {
        diversify_aes128(&[0; 16], &[]);
    }

    #[test]
    #[should_panic(expected = "1–31 bytes")]
    fn too_long_input_panics() {
        diversify_aes128(&[0; 16], &[0; 32]);
    }

    /// Each key number produces a distinct diversified key from the same
    /// master key and UID.
    #[test]
    fn ntag424_per_key_diversification() {
        let master = [0x42u8; 16];
        let uid = [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sys = b"test";

        let keys: [_; 5] = [
            KeyNumber::Key0,
            KeyNumber::Key1,
            KeyNumber::Key2,
            KeyNumber::Key3,
            KeyNumber::Key4,
        ]
        .map(|kn| diversify_ntag424(&master, &uid, kn, sys));

        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// Verify the helper builds the expected diversification input by
    /// comparing against a manual `diversify_aes128` call.
    #[test]
    fn ntag424_matches_manual_construction() {
        let master = hex_array::<16>("00112233445566778899AABBCCDDEEFF");
        let uid = [0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80];
        let sys = b"myapp";

        let mut m = alloc::vec::Vec::new();
        m.extend_from_slice(&uid);
        m.extend_from_slice(&NTAG424_AID);
        m.push(KeyNumber::Key2.as_byte());
        m.extend_from_slice(sys);

        assert_eq!(
            diversify_ntag424(&master, &uid, KeyNumber::Key2, sys),
            diversify_aes128(&master, &m),
        );
    }

    #[test]
    #[should_panic(expected = "at most 16 bytes")]
    fn ntag424_long_sysid_panics() {
        diversify_ntag424(&[0; 16], &[0; 7], KeyNumber::Key0, &[0; 17]);
    }
}
