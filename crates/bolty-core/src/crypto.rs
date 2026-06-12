//! AES-128-CMAC (RFC 4493) without the `cmac` crate dependency.

use aes::Aes128;
use aes::cipher::{Array, Block, BlockCipherEncrypt, KeyInit};

const RB: u8 = 0x87;

/// Multiply by *x* in GF(2^128): left-shift by one bit, conditionally XOR
/// the reduction polynomial `0x87` into the low byte when the high bit was set.
fn gf_double(input: &[u8; 16]) -> [u8; 16] {
    let msb_set = input[0] & 0x80 != 0;
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }
    if msb_set {
        out[15] ^= RB;
    }
    out
}

/// Compute AES-128-CMAC of `data` under `key` (RFC 4493).
pub fn aes_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(&Array::from(*key));

    // -- Subkey generation ------------------------------------------------
    // L = AES_K(0^128),  K1 = double(L),  K2 = double(K1)
    let mut l_block = Block::<Aes128>::default(); // zero block
    cipher.encrypt_block(&mut l_block);
    let mut l = [0u8; 16];
    l.copy_from_slice(&l_block);
    let k1 = gf_double(&l);
    let k2 = gf_double(&k1);

    // -- Block layout -----------------------------------------------------
    let n = data.len().div_ceil(16).max(1);
    let complete = !data.is_empty() && data.len().is_multiple_of(16);

    // -- AES-CBC-MAC ------------------------------------------------------
    let mut state = [0u8; 16]; // C_0 = 0^128
    for i in 0..n {
        let mut blk = [0u8; 16];

        if i == n - 1 {
            // Last block: copy remaining bytes, pad if needed, XOR subkey.
            let start = i * 16;
            let remaining = data.len() - start;
            blk[..remaining].copy_from_slice(&data[start..]);
            if !complete {
                blk[remaining] = 0x80; // ISO/IEC 9797-1 Method 2 padding
            }
            let sk = if complete { &k1 } else { &k2 };
            for j in 0..16 {
                blk[j] ^= sk[j];
            }
        } else {
            blk.copy_from_slice(&data[i * 16..(i + 1) * 16]);
        }

        for j in 0..16 {
            state[j] ^= blk[j];
        }

        // Encrypt the running state.
        let mut cipher_block = Block::<Aes128>::default();
        cipher_block.copy_from_slice(&state);
        cipher.encrypt_block(&mut cipher_block);
        state.copy_from_slice(&cipher_block);
    }

    state
}

#[cfg(test)]
mod tests {
    use super::aes_cmac;

    // RFC 4493 §4.2 test vectors (Example 1: empty message)
    #[test]
    fn rfc4493_empty_message() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let expected = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d,
            0x12, 0x9b, 0x75, 0x67, 0x46,
        ];
        assert_eq!(aes_cmac(&key, &[]), expected);
    }

    // RFC 4493 §4.2 test vectors (Example 2: 16-byte message)
    #[test]
    fn rfc4493_one_block() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd,
            0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        assert_eq!(aes_cmac(&key, &msg), expected);
    }

    // RFC 4493 §4.2 test vectors (Example 3: 40-byte message, not block-aligned)
    #[test]
    fn rfc4493_partial_block() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
            0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
            0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected = [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32,
            0x61, 0x14, 0x97, 0xc8, 0x27,
        ];
        assert_eq!(aes_cmac(&key, &msg), expected);
    }

    // RFC 4493 §4.2 test vectors (Example 4: 64-byte message, block-aligned)
    #[test]
    fn rfc4493_multi_block() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
            0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
            0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
            0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
            0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected = [
            0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74,
            0x17, 0x79, 0x36, 0x3c, 0xfe,
        ];
        assert_eq!(aes_cmac(&key, &msg), expected);
    }
}
