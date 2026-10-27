// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! This module implements Leakage Resilient Primitive (LRP)
//! as described in AN12304.
//!
//! LRP is a drop-in replacement for AES.

use aes::{
    Aes128,
    cipher::{
        Array, BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure,
        BlockCipherEncrypt, BlockSizeUser, InOut, KeyInit, ParBlocksSizeUser,
        consts::{U1, U16},
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) type Block = Array<u8, <aes::Aes128 as BlockSizeUser>::BlockSize>;

/// Generate the 16 secret plaintexts P[0]..P[15] derived from key `k`
/// per AN12304 §3.1.
pub(crate) fn generate_plaintexts(k: impl Into<Block>) -> [Block; 16] {
    let mut h = k.into();
    Aes128::new(&h).encrypt_block_b2b(&Array::from([0x55; 16]), &mut h);

    core::array::from_fn(|_| {
        let cipher = Aes128::new(&h);
        let mut p_i = Block::default();
        cipher.encrypt_block_b2b(&Array::from([0xaa; 16]), &mut p_i);
        cipher.encrypt_block_b2b(&Array::from([0x55; 16]), &mut h);
        p_i
    })
}

/// Generate the first `N` updated keys UK[0]..UK[N-1] derived from key `k`
/// per AN12304 §3.2.
pub(crate) fn generate_updated_keys<const N: usize>(k: impl Into<Block>) -> [Block; N] {
    let mut h = k.into();
    Aes128::new(&h).encrypt_block_b2b(&Array::from([0xaa; 16]), &mut h);

    core::array::from_fn(|_| {
        let cipher = Aes128::new(&h);
        let mut k_i = Block::default();
        cipher.encrypt_block_b2b(&Array::from([0xaa; 16]), &mut k_i);
        cipher.encrypt_block_b2b(&Array::from([0x55; 16]), &mut h);
        k_i
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct F<const M: u32>(u8);

impl<const M: u32> F<M> {
    const MODULUS: u32 = 1 << M;
    const MASK: u8 = ((1u32 << M) - 1) as u8;

    /// Construct by masking off the high bits. Always succeeds.
    const fn from_masked(v: u8) -> Self {
        F(v & Self::MASK)
    }

    const fn get(self) -> u8 {
        self.0
    }
}

type Nibble = F<4>;

fn eval_lrp(
    plaintexts: &[Block; Nibble::MODULUS as usize],
    updated_key: Block,
    inputs: &[Nibble],
    last: bool,
) -> Block {
    let mut y = updated_key;
    for x_i in inputs {
        let p = plaintexts[x_i.get() as usize];
        Aes128::new(&y).encrypt_block_b2b(&p, &mut y);
    }
    if last {
        Aes128::new(&y).encrypt_block_b2b(&Array::from([0x00; 16]), &mut y);
    }
    y
}

fn inc(counter: &mut [Nibble]) {
    for c in counter.iter_mut().rev() {
        let v = c.get();
        if v == Nibble::MASK {
            *c = Nibble::from_masked(0);
        } else {
            *c = Nibble::from_masked(v + 1);
            return;
        }
    }
}

/// Maximum LRICB counter/IV length in bytes. Comfortably covers every
/// NTAG 424 DNA counter (≤ 8 bytes).
const LRICB_COUNTER_MAX_BYTES: usize = 16;

/// LRP exposed as a 16-byte block cipher.
///
/// This follows AN12304 §2.2 Algorithm 3 with `final = true`.
///
/// Implements the `cipher` crate's encryption traits, which gives an automatic
/// `cmac::block_api::CmacCipher` impl via the blanket `impl` in the `cmac` crate.
/// Together with `cmac::Cmac<Lrp>` this computes AN12304 §2.4 LRP-CMAC.
#[derive(Clone)]
pub struct Lrp {
    plaintexts: [Block; 16],
    k_prime: Block,
}

impl Lrp {
    /// Build an LRP instance from a base key.
    ///
    /// Uses `UK[0]` as `k'`, the NTAG 424 DNA MACing key.
    pub fn from_base_key(key: impl Into<Block>) -> Self {
        let key = key.into();
        let plaintexts = generate_plaintexts(key);
        let [k_prime] = generate_updated_keys::<1>(key);
        Self {
            plaintexts,
            k_prime,
        }
    }

    /// Build LRP from precomputed plaintexts and an explicit updated key `k'`.
    pub fn from_parts(plaintexts: [Block; 16], k_prime: impl Into<Block>) -> Self {
        Self {
            plaintexts,
            k_prime: k_prime.into(),
        }
    }

    /// Access to the underlying `k'` (updated key). Used by in-crate tests
    /// to compare against known-good NXP worked examples.
    #[cfg(test)]
    pub(crate) fn k_prime(&self) -> &Block {
        &self.k_prime
    }

    /// Load a counter into the nibble scratch buffer.
    ///
    /// The counter is treated as a big-endian nibble string with two
    /// nibbles per byte, high nibble first. Empty counters and counters
    /// longer than [`LRICB_COUNTER_MAX_BYTES`] are rejected.
    fn load_counter<'a>(
        counter: &[u8],
        buf: &'a mut [Nibble; LRICB_COUNTER_MAX_BYTES * 2],
    ) -> Option<&'a mut [Nibble]> {
        if counter.is_empty() || counter.len() > LRICB_COUNTER_MAX_BYTES {
            return None;
        }
        for (i, &b) in counter.iter().enumerate() {
            buf[2 * i] = Nibble::from_masked(b >> 4);
            buf[2 * i + 1] = Nibble::from_masked(b);
        }
        Some(&mut buf[..counter.len() * 2])
    }

    /// Pack `nibs` back into `counter` (two nibbles per byte, high first).
    fn store_counter(nibs: &[Nibble], counter: &mut [u8]) {
        for (i, b) in counter.iter_mut().enumerate() {
            *b = (nibs[2 * i].get() << 4) | nibs[2 * i + 1].get();
        }
    }

    /// In-place `LRICBEnc` without padding (AN12304 §3.3). `buf.len()` must
    /// be a positive multiple of 16 - any ISO/IEC 9797‑1 Method 2 padding
    /// must be applied by the caller. `counter` is advanced in place by one
    /// per processed block, matching the NTAG 424 DNA `EncCtr` rule.
    ///
    /// Returns `None` on invalid `buf` length or unsupported counter length.
    pub fn lricb_encrypt_in_place(&self, counter: &mut [u8], buf: &mut [u8]) -> Option<()> {
        if buf.is_empty() || !buf.len().is_multiple_of(16) {
            return None;
        }
        let mut nibbles_buf = [Nibble::from_masked(0); LRICB_COUNTER_MAX_BYTES * 2];
        let nibs = Self::load_counter(counter, &mut nibbles_buf)?;

        for chunk in buf.as_chunks_mut::<16>().0 {
            let pt_block = Block::from(*chunk);
            let y = eval_lrp(&self.plaintexts, self.k_prime, nibs, true);
            let mut ct_block = Block::default();
            Aes128::new(&y).encrypt_block_b2b(&pt_block, &mut ct_block);
            chunk.copy_from_slice(&ct_block);
            inc(nibs);
        }
        Self::store_counter(nibs, counter);
        Some(())
    }

    /// In-place `LRICBDec` without padding (AN12304 §3.3). `buf.len()` must
    /// be a positive multiple of 16. `counter` is advanced in place by one
    /// per processed block.
    ///
    /// Returns `None` on invalid `buf` length or unsupported counter length.
    pub fn lricb_decrypt_in_place(&self, counter: &mut [u8], buf: &mut [u8]) -> Option<()> {
        if buf.is_empty() || !buf.len().is_multiple_of(16) {
            return None;
        }
        let mut nibbles_buf = [Nibble::from_masked(0); LRICB_COUNTER_MAX_BYTES * 2];
        let nibs = Self::load_counter(counter, &mut nibbles_buf)?;

        for chunk in buf.as_chunks_mut::<16>().0 {
            let ct_block = Block::from(*chunk);
            let y = eval_lrp(&self.plaintexts, self.k_prime, nibs, true);
            let mut pt_block = Block::default();
            Aes128::new(&y).decrypt_block_b2b(&ct_block, &mut pt_block);
            chunk.copy_from_slice(&pt_block);
            inc(nibs);
        }
        Self::store_counter(nibs, counter);
        Some(())
    }
}

impl Zeroize for Lrp {
    fn zeroize(&mut self) {
        for p in self.plaintexts.iter_mut() {
            let bytes: &mut [u8] = p.as_mut();
            bytes.zeroize();
        }
        let k: &mut [u8] = self.k_prime.as_mut();
        k.zeroize();
    }
}

impl Drop for Lrp {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Lrp {}

impl BlockSizeUser for Lrp {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Lrp {
    type ParBlocksSize = U1;
}

impl BlockCipherEncBackend for Lrp {
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block>) {
        let input = *block.get_in();
        let nibbles: [Nibble; 32] = core::array::from_fn(|i| {
            let byte = input[i / 2];
            let nib = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
            Nibble::from_masked(nib)
        });
        *block.get_out() = eval_lrp(&self.plaintexts, self.k_prime, &nibbles, true);
    }
}

impl BlockCipherEncrypt for Lrp {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
        f.call(self);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    use crate::testing::{hex_array, hex_bytes, hex_nib};
    use alloc::vec::Vec;

    fn hex_nibbles(s: &str) -> Vec<Nibble> {
        s.bytes().map(|c| Nibble::from_masked(hex_nib(c))).collect()
    }

    // Test vector from NXP AN12304, section 3.1
    const BASE_KEY: [u8; 16] = [
        0x56, 0x78, 0x26, 0xB8, 0xDA, 0x8E, 0x76, 0x84, 0x32, 0xA9, 0x54, 0x8D, 0xBE, 0x4A, 0xA3,
        0xA0,
    ];

    #[rustfmt::skip]
    const P: [[u8; 16]; 16] = [
        [0xAC, 0x20, 0xD3, 0x9F, 0x53, 0x41, 0xFE, 0x98, 0xDF, 0xCA, 0x21, 0xDA, 0x86, 0xBA, 0x79, 0x14],
        [0x90, 0x7D, 0xA0, 0x3D, 0x67, 0x24, 0x49, 0x16, 0x69, 0x15, 0xE4, 0x56, 0x3E, 0x08, 0x9D, 0x6D],
        [0x92, 0xFA, 0xA8, 0xB8, 0x78, 0xCC, 0xD5, 0x0C, 0x63, 0x13, 0xDB, 0x59, 0x09, 0x9D, 0xCC, 0xE8],
        [0x37, 0x2F, 0xA1, 0x3D, 0xD4, 0x3E, 0xFD, 0x41, 0x98, 0x59, 0xDC, 0xBC, 0xFC, 0xEF, 0xFB, 0xF8],
        [0x5F, 0xE2, 0xE4, 0x68, 0x95, 0x8B, 0x6B, 0x05, 0xC8, 0xA0, 0x34, 0xF3, 0x38, 0x23, 0xCF, 0x1B],
        [0xAB, 0x75, 0xE2, 0xFA, 0x6D, 0xCC, 0xBA, 0xA0, 0x4E, 0x85, 0xD0, 0x7F, 0xB9, 0x4E, 0xED, 0x28],
        [0xAC, 0x05, 0xBC, 0xDA, 0xC4, 0x4B, 0x14, 0xBF, 0xFD, 0xF8, 0x90, 0x74, 0x98, 0x69, 0x53, 0x89],
        [0x0A, 0xF9, 0x75, 0xED, 0x75, 0x29, 0x42, 0xD7, 0x56, 0xA8, 0xA9, 0x7C, 0x78, 0xC0, 0x9C, 0xD8],
        [0x4F, 0x58, 0xAF, 0xB5, 0x7C, 0xAD, 0x5F, 0xE1, 0x6C, 0x03, 0x3F, 0x9D, 0xF5, 0xB5, 0xB3, 0xFE],
        [0x56, 0x98, 0xD7, 0xB5, 0xF5, 0x95, 0x66, 0x14, 0xD5, 0x7B, 0x5A, 0x18, 0xB9, 0xB8, 0x81, 0x0E],
        [0x5A, 0xC8, 0xCF, 0xBA, 0x77, 0xF7, 0xC6, 0xA6, 0x13, 0x48, 0xAF, 0xB9, 0x2B, 0x11, 0x95, 0xCA],
        [0x01, 0x2D, 0x66, 0x10, 0x89, 0x16, 0xE2, 0x9A, 0x86, 0xE8, 0x81, 0x46, 0xA1, 0x04, 0x7D, 0x3A],
        [0x25, 0xF8, 0xF9, 0x25, 0x46, 0xDB, 0xA8, 0x65, 0x11, 0x91, 0x46, 0xFC, 0x9B, 0x26, 0x0B, 0xCA],
        [0xBE, 0x9E, 0xE4, 0x4F, 0xC4, 0x2D, 0x8C, 0x73, 0xC6, 0x5E, 0x2B, 0x6D, 0x0B, 0x24, 0x54, 0xEB],
        [0x37, 0xD7, 0x34, 0xA5, 0x1C, 0x07, 0x6E, 0xB8, 0x03, 0xBD, 0x53, 0x0E, 0x17, 0xEB, 0x87, 0xDC],
        [0x71, 0xB4, 0x44, 0xAF, 0x25, 0x7A, 0x93, 0x21, 0x53, 0x11, 0xD7, 0x58, 0xDD, 0x33, 0x32, 0x47],
    ];

    #[rustfmt::skip]
    const UK: [[u8; 16]; 3] = [
        [0x16, 0x3D, 0x14, 0xED, 0x24, 0xED, 0x93, 0x53, 0x73, 0x56, 0x8E, 0xC5, 0x21, 0xE9, 0x6C, 0xF4],
        [0x1C, 0x51, 0x9C, 0x00, 0x02, 0x08, 0xB9, 0x5A, 0x39, 0xA6, 0x5D, 0xB0, 0x58, 0x32, 0x71, 0x88],
        [0xFE, 0x30, 0xAB, 0x50, 0x46, 0x7E, 0x61, 0x78, 0x3B, 0xFE, 0x6B, 0x5E, 0x05, 0x60, 0x16, 0x0E],
    ];

    #[test]
    fn plaintexts_an12304() {
        let got = generate_plaintexts(BASE_KEY);
        for i in 0..16 {
            assert_eq!(got[i].as_slice(), &P[i], "P[{i}]");
        }
    }

    #[test]
    fn updated_keys_an12304() {
        let got = generate_updated_keys::<3>(BASE_KEY);
        for i in 0..3 {
            assert_eq!(got[i].as_slice(), &UK[i], "UK[{i}]");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "50 LRP vectors; native CI already covers correctness")]
    fn eval_an12304_vectors() {
        struct V {
            key: &'static str,
            iv: &'static str,
            finalize: bool,
            uk: usize,
            res: &'static str,
        }

        #[rustfmt::skip]
        let vectors = [
            V { key: "567826B8DA8E768432A9548DBE4AA3A0", iv: "1359",                             finalize: true,  uk: 2, res: "1BA2C0C578996BC497DD181C6885A9DD" },
            V { key: "B65557CE0E9B4C5886F232200113562B", iv: "BB4FCF27C94076F756AB030D",         finalize: false, uk: 1, res: "6FDFA8D2A6AA8476BF94E71F25637F96" },
            V { key: "88B95581002057A93E421EFE4076338B", iv: "77299D",                           finalize: true,  uk: 2, res: "E9C04556A214AC3297B83E4BDF46F142" },
            V { key: "C48A8E8B16571645A1557825AA66AC91", iv: "1F0B7C0DB12889CA436CABB78BE42F9",  finalize: true,  uk: 3, res: "51296B5E6D3B8DB8A1A7399760A19189" },
            V { key: "CAF3750AFF93F9A0C8861BCCCCDF1A9D", iv: "9273B7",                           finalize: false, uk: 3, res: "468C2BFCF993E7F112E150C17298A968" },
            V { key: "65024B14AA99E9CA93F51172E19EE000", iv: "826CE8A26DFE768D91",               finalize: true,  uk: 1, res: "A3830865D52EAEBC6471CDBD3DFC0A89" },
            V { key: "1EDB9D253DF18D72BEEAE960B6FDF325", iv: "FD7BBC6CE819F04AF0C3944C9E",       finalize: false, uk: 3, res: "B73B50D4BA439DF9D4AFB79FF10F1446" },
            V { key: "08CFACB758EB34F0106D42358F22B5EB", iv: "431B8F155EB1F28334F201CADD7",      finalize: true,  uk: 1, res: "40C01FC5DF4C142D9C9721F74A373BA5" },
            V { key: "CC57E7503BCCCF260D6B4E2AB38ACE94", iv: "4D09838DF371FAC5D5B641EE45",       finalize: false, uk: 3, res: "C1A465936A097FF76FCAF18166E8DF60" },
            V { key: "D0E9C3CACE9A747A74F582AA0F873FF9", iv: "FCB69068C83E64765676F718E41E25",   finalize: true,  uk: 2, res: "A944D5A19C5B86392CC3CFC58F57C321" },
            V { key: "59C9C703C66A9FD2948E0A48617285DC", iv: "F28EFF672184665744FD835B106484",   finalize: true,  uk: 0, res: "F078390B345FC6E22EE9A75B3D8BF490" },
            V { key: "2E763263979117BED33A331B15E3F01B", iv: "2B96BFF1A8429C6E",                 finalize: false, uk: 3, res: "9193DA3870AA345EB4FDFB5EE4A35E61" },
            V { key: "A14E397DA6C410440FA9EC4C61774094", iv: "4B42600D",                         finalize: true,  uk: 0, res: "21C0B442BF41B7DDD80D4A99CD7B7B81" },
            V { key: "921038ED913CCEEFC6286B756F9ABC8D", iv: "9FE171DCB4CA1F7E5",                finalize: true,  uk: 0, res: "9FF1DBB5E8528E56370EB55919642AC0" },
            V { key: "F2512BC694E7A66D6ED67E0841BA2523", iv: "D0F92AC3F33EC12CF5B65C6ECE12DE0",  finalize: true,  uk: 3, res: "6271F38386E7399D7FA1709A72B4F585" },
            V { key: "75FCA5E188F44F1E808597A0B7B690D4", iv: "64962F5DED0468F1",                 finalize: true,  uk: 1, res: "EBD6F32ED75566E6756A14EC16715CBD" },
            V { key: "1000076C2934BDB02750204704DAA472", iv: "8C3E0",                            finalize: true,  uk: 2, res: "581C3B057F9312FECF4A7B8070C83B8C" },
            V { key: "99B1647A76CD170EA07997043E1E7919", iv: "F",                                finalize: true,  uk: 1, res: "BA5F895E8B57F7753EE5C7276E60B37F" },
            V { key: "6983FC665FBB8BEA35DADBB2EF446656", iv: "BDF09818B0A7AFFF9C8",              finalize: true,  uk: 1, res: "E0A4144033A1CACD1DBCE30F9883A1DB" },
            V { key: "9FBC2045FA6215B4FD1ABA412DD9C59D", iv: "F9B72310BDAE086C51D354B65F1F05F1", finalize: true,  uk: 1, res: "3F410411D5ED704572D06EDE6AB45CA2" },
            V { key: "1EBB6DF4E251A10B9503AE6B3EEB0ACA", iv: "CDD68EFF713C8",                    finalize: false, uk: 3, res: "28740D45D92737D6CF8F05D05B961424" },
            V { key: "415F46BA9A3C3C44A7E1782117668105", iv: "590012E84AEC7",                    finalize: false, uk: 2, res: "9852EFC35E53F2A4E8DA55770123C99D" },
            V { key: "371A061E4A3065D00F41C4DA68722FFA", iv: "52C78A675488D",                    finalize: false, uk: 3, res: "FD2BDCC3EA26AF2069A4C536E3D6B33B" },
            V { key: "E28DFE591559441D04213D889747BC46", iv: "414E42E7",                         finalize: true,  uk: 2, res: "5E8BF483C2D6DA906EC58D1B63AC9887" },
            V { key: "18A4209AAEF2CFC67E48834ED7D2B62B", iv: "4B6E0EBCBB920A0B441114478",        finalize: false, uk: 0, res: "D054F91224DAC4C9E46EDF7EFAB6D179" },
            V { key: "FBBCE5B5F4BF962A345BBF3F13F9E474", iv: "D6B8F778C25",                      finalize: true,  uk: 2, res: "73C265CD18C9F909784DCFC4CAA5109D" },
            V { key: "8E90A2AEBEB136C000521AEC0037ACFF", iv: "B3FD7B7F1026CF70FF71CF8",          finalize: false, uk: 3, res: "7F519F9B9EAB01EF8DED79520C46770E" },
            V { key: "FA89CC662EF47C75A9887F12A6C9879F", iv: "B9",                               finalize: true,  uk: 0, res: "4973ECE66EEE903D4761EF3960210735" },
            V { key: "3F0E5E6D0F7F7BDE4DB2C4F074D02062", iv: "7D0AA4C30A75FC6C6A5D47D12247",     finalize: true,  uk: 3, res: "87F43A64DAF93DF744F54FECE1A480AB" },
            V { key: "B443EC2B5E56AF789D27F6C38F9DD6A9", iv: "0CACAE327B04E870A3151E967",        finalize: false, uk: 0, res: "795553EBFA89AD541C0ED2E5F3C4611F" },
            V { key: "7DD9BF8D3337D57ACD92069B13B16CCE", iv: "2266169A6882C7E84",                finalize: true,  uk: 0, res: "49F4FFFEA580EC96D5DCACC9E10AA95E" },
            V { key: "B39A5A07AB6746B5DE4875ED9492DF1B", iv: "F03704D4806A731",                  finalize: false, uk: 3, res: "635E39AEF94D050B5424E1D967027594" },
            V { key: "E2703DC54BF4E7C63337FFF0AB6BB6F0", iv: "35D183BB4C56E8F70B",               finalize: true,  uk: 1, res: "3E537D77DE31EA05C33CE70B4ECE65FA" },
            V { key: "DF19EF9394EE6344A0832AF8ADCBABE4", iv: "44CB4DE4352D3E45F5",               finalize: true,  uk: 1, res: "80F1A5169142107FF0873BC4222E8173" },
            V { key: "24E6DD53E9FEE719486C5CBD07714FC8", iv: "24B80F682AF9B33",                  finalize: true,  uk: 0, res: "4FA0477728E34E1408D98643F8124035" },
            V { key: "FAE4C2544FF93C20BAA6D60FAFE4919B", iv: "87C4DB",                           finalize: true,  uk: 0, res: "FD2847D87ADC24C27FA042D1DCA1459B" },
            V { key: "6D1902203D17BCBCE3A0A961EC358517", iv: "CA5195213C2C75D37DCC6A67",         finalize: true,  uk: 3, res: "2EADE5706A4BCD7CAF844DE01B127CE0" },
            V { key: "7BC16676A8522EBC2564FEC235654DF8", iv: "A885",                             finalize: true,  uk: 0, res: "9819FE9556933E1CFC4E99C8BF64ACFA" },
            V { key: "F989FF4BDDD5AB6999EF517B742EA085", iv: "C4DE07A5E",                        finalize: false, uk: 0, res: "D6FEE60DBC8BA533E320ED1D18076D82" },
            V { key: "5F07C727DA21B6C1E2688237672BCB7D", iv: "8C74AC47C037AD729D38E3A",          finalize: false, uk: 0, res: "6021FC212F818102027C61FCE28D382C" },
            V { key: "549C67ECD60E848F773990990CAC681E", iv: "475BB41878EB17468F7A68847DDD3BAC", finalize: true,  uk: 3, res: "C3B5EE74A722E784887C4C9FDB497855" },
            V { key: "9AFF3EF56FFEC3153B1CADB48B445409", iv: "4B073B247CD48F7E0A",               finalize: false, uk: 3, res: "909415E5C8BE77563050F2227E17C0E4" },
            V { key: "F2BBB25D607ECD1E551CD75CF0033CCE", iv: "0335137B5641EFA4F176836A65F0F49",  finalize: true,  uk: 0, res: "87832A9AF79C6CE436EA4DB6CAB18203" },
            V { key: "806A50530D7735B40AC4EF1638E8AD6A", iv: "D4137764716DBC8C579BEAB7E76754E",  finalize: false, uk: 3, res: "CF991392F0369350A7E21BE52F748821" },
            V { key: "64193EF6BDDDC74C7C008DB98ED5FF67", iv: "89AB",                             finalize: true,  uk: 3, res: "4A828E35DBADF6A465321363717D0D27" },
            V { key: "F9E29780209AC952DD87C2572C4950BF", iv: "35AF18F46C2FD3C8C6EB507147CA35A",  finalize: true,  uk: 1, res: "51F3482AB8880850390F4F6D775F5C1F" },
            V { key: "37A6769D43FEFA9F79CA61628BAFA7F1", iv: "FB",                               finalize: true,  uk: 0, res: "81C84283D18071F08DE72AD51B5826B6" },
            V { key: "047568AC57D4DE026C40F7228BDD1819", iv: "F1B11",                            finalize: false, uk: 3, res: "9CE6BEC0F80FDF7D78B1C219130102E7" },
            V { key: "F36472663A3BA87F3E76399C66C23EC9", iv: "1FF73338D23ED6AE968",              finalize: true,  uk: 1, res: "36DA0902796F4682034DB07D0FF58E28" },
            V { key: "906249E5AF810339F199A25AEC0281E8", iv: "56DA443282912622BB92338F8CA",      finalize: true,  uk: 2, res: "317600A76B5A7984A681D1D8855F86FC" },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let key = hex_array(v.key);
            let plaintexts = generate_plaintexts(key);
            let uk = generate_updated_keys::<4>(key)[v.uk];
            let nibbles = hex_nibbles(v.iv);
            let got = eval_lrp(&plaintexts, uk, &nibbles, v.finalize);
            let want: [u8; 16] = hex_array(v.res);
            assert_eq!(got.as_slice(), &want[..], "vector {i}");
        }
    }

    // Test vectors from NXP AN12304, section 3.3. k' is always k_0.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "AN12304 LRICB vectors; native CI already covers correctness"
    )]
    fn lricb_an12304_vectors() {
        struct V {
            key: &'static str,
            iv: &'static str,
            pad: bool,
            pt: &'static str,
            ct: &'static str,
        }

        #[rustfmt::skip]
        let vectors = [
            V { key: "E0C4935FF0C254CD2CEF8FDDC32460CF", iv: "C3315DBF", pad: true,  pt: "012D7F1653CAF6503C6AB0C1010E8CB0", ct: "FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623" },
            V { key: "EFA5B7429CD153BF0086DEF900C0F235", iv: "9036FFFF", pad: false, pt: "E7F61E012F4F3255312BA68B1D2FDABF", ct: "EA6E09AC2FB97E102D8CA64C1CBC0C0C" },
            V { key: "15CDECFC507C777B31CA4D6562D809F2", iv: "5B29FFFF", pad: false, pt: "AA8EC68E0519914D8F00CFD8EA226B7E", ct: "C8FBD3842E69C8E2EBCA96CE28AB02F0" },
            V { key: "A2D06401CDF35822B430F4457D1D1775", iv: "5C35A6ED", pad: true,
                pt: "D2D83A1971077EDDFE2DF28DF9B736A4D9D4244BCF72E9597CB47B7DCDB5A4B245B52080E79BBFEDC69F1EE983CE",
                ct: "73B1BED57B59090BC496799FA9BFE9F5252A88350A8F48A4FF252B8E813F6D96CA8BA7C8162E4CB2DFE0D53800FF01DA" },
            V { key: "3CEEB70C13578D714860EEE19DBC8B01", iv: "104988FF", pad: false, pt: "3E1537842F53FFD5AD788DC6C0A14D25", ct: "0EFEEAE6249011EF6CD2D28980B93766" },
            V { key: "D36CC09105FD0261C58FD5604486F757", iv: "01FFFFFF", pad: false,
                pt: "EF44FE3B50A73B1974D7D624B74012D5BEA07D9F91278035C470CD0BD0E753B2A2F90DBE638A3F2E252A112081DC98942F802D788F4F7AC8C3C876DFDA30498D842382BD32537134614F7A671660B4E8D738DB50B9DA23527F45FA9B145F54F4E0839C5D5ADA61DC0EF91740D513B263148E08A155F9D4A9002F3EED58D62002FA858692C3578DFDD7FE41BFC2E27D6C",
                ct: "F72471266DE22E2C66A6B89F20CA00859B63A41E396A592EF6673E3A5220DF70B9E0D3EFF3503F81F203573871CD5006679A10071B861C3A71B02B86C766576F35DE0790913E7A429C28DB6C398FEA5F9E140F92F5C6729F7FFAD38DE456F1D6222569B461568091B305AB69F19930BC489D18B8C3D6FA7B3D37467E4F3A6C9577E8C285C375A0B73970016BDB288AE4" },
            V { key: "9397878556B29FE7AFF25C2A9C748338", iv: "D9154550", pad: true,
                pt: "CA56B814E61EB2D25AC14E9AAB48E59FE3D0FB6360637B09E6",
                ct: "E1D03C38C92DDF5A7C5A3FC1AA52E74627192A01143D26E8F592EE5D3C335168" },
            V { key: "AD9C2DDF73F7CA844BE8492F9A0C3D77", iv: "C9FFFFFF", pad: false,
                pt: "CEC19DAA67DAAE2E398185F2E6CA84155F5F9C7048C4BDEB9649B920A7429FC3F2372809E7A1816E806BD2BCF2D732F764290B9ECE7CF30A04B1131D218E87F6E2C2FFAFA17A2DBDDD2DF0DCF101F8BF",
                ct: "AA8D27EFC3D3ABF80A487C6C3577B2AB6B2FAA4317C0B3EFBB8C9A301F21C5FD2FE0E2E27B6516B8678121091A411D8A08B7E1111E9DB13DB169B2D3052007679E84BE742D4AEABD11FAE5624D49EDE0" },
            V { key: "16C1BB7D3701F476431E05368D634DF2", iv: "E4DCDA30", pad: false,
                pt: "4DC0A08C161803B9540760D209BFE1CD896C8375F72F79E0FEF81527C8E8936BD182E94054EA2D05027D395CED1FDA1CF8634D16D274031E46C08E1D03DCF06C74F40187D6A0789F3F7D737AF51DF3DE1EF92E649A7C985D7ECAFA945C0F02268CCDE8F81D524558EAAED75500892829CCAFFF09AD8CD1F75CA4090CA5E4422F7B4DEE2835FAC0CBB3D579EBA4435CF5A1D1C7AC0FF878FFFCF09B794939B2066BA7D9B39A00F3D1EE3356D812E5521947146AD41D961F83D5EE2B445F47827A227380FD69A85AA1DDF5BEDBA29FED16",
                ct: "B1CF729E877227D606F104827ED07334FBF1AA7782341C77BBEB31EFAB36B96344431098AB2658A5D7F7ADA4B60680C5727F418037DEF71DA1A12AD4C621C74CCD0C3923769798BF7B401C91AA23B060358B7BB3FA831B1D06A85ED5EA8B0A8B1747BCC6D64D3639F8D1B8EBB633C4A02279B59C7E250113080B0240C2947E73BC774B8A1A981F85FE9C18D1C9BA025954E803C08756FC1FD9B83E0CF56C41EC6D32C0EE1946CD6E80E541CC9A0A407C6D171855D0793080A0FE423A0D1B63C45C03F7789552F28E72849DCC42F31F91" },
            V { key: "9D813134CFDEE9D58755DEACD4AF72A7", iv: "FFFFFFFF", pad: true,  pt: "27", ct: "F5833FC397356EA3D9ECADBB9F6FE440" },
            V { key: "D744E1350115A7DD154DAA448AAA7513", iv: "CAAECC2D", pad: false, pt: "E94EB047D1927A06E6C1FE4374A8AABE", ct: "5A00BAA47E1753668D605A1998843DC8" },
            V { key: "08949164317113BBE09CD40CFCC9A4C0", iv: "191B4BB2", pad: true,
                pt: "5EC9AC319F21030D25EE85C595783BF56635BE6E0A1C1D3E2A585CF859A8880E918C134A0EAFFCB208EEA3B53A5386D3",
                ct: "AE617C37C4F55FD711DFD2E3025524C7CA08571CC556A3C85C3BFC9652916070D1CEF452A089F65BE4A981EA9694CCF1133087AB70D7FCC7EC9496F4F83ADEA5" },
            V { key: "7770F8D6C4639941AB6E0746C40AB47C", iv: "65773408", pad: false,
                pt: "0B651B786704D6D28981E9B0B24A2EF2D19EA0A7B5EDFE3A274FC31F7E6D8689409DB8FD7EC8446A31743B89CBCCB32C",
                ct: "55BEB785703EDE175B4EA69054023EB3CF3996C55D3D0FD5D8ED757C397E066C1453ADC6879FF2F501765524CAE5AA27" },
            V { key: "061593514510831E67E1511741B6541C", iv: "FA5F6F15", pad: true,
                pt: "7641B2746F5A9C961968DA3544301999969C762C297A1F1E8F6C5D9E9AD5A089F60F99416BF372F77BAA9DEB42C51B3EFBF899D7932E0DFB2193E502FCFEFB43C7503E3497D82EA32A7EB17EDD34DCC9511EA2A23CC9F6C8029D20D80D6FFA7CAE5923F187E6A723C9F6AC14",
                ct: "B3CB99514F0AFE7151C3743FAF7DB17E622529CE16F3BB9203BA7DBE45DC89CB3AFDEF19F47CA9BEB54B46F0AB3347FC80BCE7BDF21A2DDB4EB6A425923977FD201A8163865E9BD73B4384702BAF33E7D693DE4D8F6DA00097133E3AA77E25BD5277A24DF1361B5F4725C9FE4CF89145" },
            V { key: "7C8E1EEDB71BB1DE5B5907FE5A7532F9", iv: "B85695BB", pad: true,  pt: "426A777FD8451CE14C737F3221F1BD1C", ct: "9B5C42B96086FB2A9A9AC0B280F020B4B4734EBAD2D6A73BE758B9C8CC7226E5" },
            V { key: "215551249711B3AE6B7361F19048BF9A", iv: "DCCCFFFF", pad: false, pt: "7929BF798535A3FE67127A32EC5330B7", ct: "6C4D5A30B3102D627721D19EDDCEC534" },
            V { key: "C91464E42B5004B4E556541876B546D4", iv: "8F421EFF", pad: true,  pt: "354467EF78A8909DC61CDEB628250A94", ct: "0ADA577B841FC5CB112230336B33CDA72E17D303D05EC66CAECF892B0C282DF5" },
            V { key: "2EE08B87B1CCA5A2A93548C2952E2526", iv: "3827CF6F", pad: true,  pt: "B8B18B", ct: "29E99882A0DCED4E55FB3E61303DE275" },
            V { key: "F5C3E99FB75E316B76689FC5464260CD", iv: "0797F6B7", pad: true,  pt: "", ct: "93DC3EE14B612BE6A3E9E2E8040CDFCB" },
            V { key: "C7031CA1994DECF01D4084D8F577C6F5", iv: "CDB066D0", pad: true,  pt: "", ct: "3B1DAAC45010793FD592FB76827796A5" },
            V { key: "10E7C2FA0DF36D4E89F05B15C9DD1BB2", iv: "D42802DB", pad: false, pt: "B150EFCB5EA66A0D8888652AF6104C17", ct: "ACA71BCE7E9057EA8B834B37BF028D1C" },
            V { key: "896B876BDF03D34B1DE3F8973323FDC7", iv: "FFFFFFFF", pad: false,
                pt: "4054B588DE18B6C46BA699C3E2AD7DA3AD7AADD3DA658A9D97BDB3A99805403D7BD7C27E959405E0E16EB7572ECF55AE25DBD5B09C1D2EDACA18F120640C2C66665C480BEAFF0D1975CDF26BAD336FC7",
                ct: "60801EEFA4D5506A73753F826F82EFE6B02E6579BB654256BAC5C7ED81E16A190BF8953A056FB869A9C5C10C87AE3FDE28CE32730B290F4EB0062E96AB29B40F764AD5D8ACE61997EC515BB69B24E6C0" },
            V { key: "680583BD2F90A05DA9E8B37DA2E47CD4", iv: "4151F0D2", pad: true,
                pt: "3BCE2BC22D96A92AB85E896F36D6BBEA6102",
                ct: "82A7917C5D9B16C8B01277F3E4FF6BD14BF404176F344188F7F8AB2D072C0F99" },
            V { key: "4B8F7691511E2A5C429C401D415CEE73", iv: "55D131FF", pad: true,  pt: "D2", ct: "83FF5F0382BC7EA5C795122C83D3B0C2" },
            V { key: "1B1A179CE9C0DB3E45A97D0D98D0530C", iv: "E9FFFFFF", pad: false,
                pt: "472DBAFE6434D357402785A3348081B02EAB54244EE9C9C88E91001C5158992DE36E79AD844645493940902C8746669B",
                ct: "397C9EFFD28C560411B934895C8DF60F082B9560778F8571B5C31A057B34C2352F11B5634788623499C6BDD5C490F5CB" },
            V { key: "ABD094D694942C5E64F26FD333B705E7", iv: "8E57BFC6", pad: true,  pt: "", ct: "C96E153DDBEC9B8CE23A142A34230CD1" },
            V { key: "EA0D599D41482A647081C4C3994F411A", iv: "48FFFFFF", pad: false,
                pt: "86A093D7A4AC7089A91E04C7B127A8CE468423CABE6F84ED8B9A10F4F568D3B1FF11C18AD099DC18530FA6231681E0AFC8473CB585D371161CA64C0A9C7B94414B53C79F661EFDADA80B76AEC960D609B9602CAE2B1D2B2CA0AA6E2A4CD27BD87A65D8C3BA4149A9498F0D7A5CC24DBB",
                ct: "557D92979767DF003FAC2D865C5650FB00936AE565D4413A506E82DA0BADED4CCA98E0F82A602893AE2C8122F2757E3F20AB6AB5D66EED94F2C7908E3AB0F03F1B6FD87DF5FB347C0A8A8F8C8334B4A89D66D4ACA4D5E1AC398F9198723A54EAE62E52A331D18E2F252C2737DDA6A950" },
            V { key: "D042503B4FE6152D279BFFBBB0D360D5", iv: "8F9E3364", pad: true,  pt: "649C0FB1CFDD5CB2590A814089944FAA", ct: "7BB7E3DA21CBCCEAAEDB71798114656C331C7D2DCD661C43F679FC50FA0239E5" },
            V { key: "9B1E418DF9752F37EBBD8EE833BDF2D7", iv: "24FFFFFF", pad: true,
                pt: "55534E159F14DD7731368988EE6DD7C6114E747F9C17A91BBC12D68C26531F2FFCFC",
                ct: "158B3B9C6136FB715CCF435CA4CADE808D1F98431327061A9A64D52A5FE7B2746D7F5A633FC0CFE7855656AD3C6B94CF" },
            V { key: "D9E39CA8EFD45645C1A19B44920B46AE", iv: "B9D3EA7D", pad: true,
                pt: "3D5050DD16598BF294F32A695F9F2956560880787FCB4677994C447F1F9B39694F629605F5E38A41B8A077528450734A5486E7A1B2E00D7209D943CA150CD3F9BAC119FD092361727E3FBFDF53F4F249",
                ct: "0241258DBBC6395735FE6F8B81BB958A3758FD7C772F801EA689A1B3DB83D711CC0E16CF08AEFB39E3DF50551AAB8293E16085B0B7805C2CCFB9A0D2E8FC73542C844A35A9B352F750F8E9344591E2BEC55C87E4AFDE1FA5FAB6AF09357EF28C" },
            V { key: "D9F92A98B398B76E5523FC1B9FC02CAB", iv: "CC7E98C3", pad: false,
                pt: "752273212D1F14E6FAF01BE13A452109ABA7E52646D2BE121313D55C2F1262B8F9743D76434D2704E735A5CF10CA913876B98BCE5B0ADEA263600D1A49B7B6E78D63E7C607AAC65D7FE13E112DEF0249819CE57687945CEF959B13E33F0DBA307EBD41ADE2CA30CCF32D4E7ACBCD75745EC498ADD14060F906F8316C97E21E72260E936FAD5466B66B19825A45E224C8259E847B740D5E3D5D48A7EA99C334100EDC54BC3A06C60A5DE141B8BE06B323D36847F85DA3FD18B0551265AC7C1DA7E4714B698E678E1ED87A1E92CCA67E57",
                ct: "6CF4254823B6A182B155A4280F5DD9B86F83968BCA07ABB552077647446C5AE41584B964CB69C03B84BBA9CD181AF60848488B355B058FBEC74FFF11F5A4F05AD15138FA2C4C71BA0AB15C35EDEA9958F6C1904CEC673936554611A47BEDEC467387B99E4D3415C716AECA75039F4FBDB19BE15E042E81522CD819122D3B9D007B9D5DF4A11AFC4FEB58DE24821CE507B2B2B720355E3B23275B05AC543C61EC3905B01B1B3704A86577FE7B4204FC848AF94E612C2A168568D4F44326113AEB7F767E5B43A4B3B2987EDDBD279A8E37" },
            V { key: "948316307C3CB26BDE3B0CE4F4605DE0", iv: "C4FFFFFF", pad: false, pt: "20E3846A4C09D7BAD12965EC2BA8BFDF", ct: "BB1942D3E6F866ADD796B7EA85755D57" },
            V { key: "8A525AA92A771D3DCE32D2329C49EEAA", iv: "5653FFFF", pad: true,  pt: "33", ct: "352BBE318443FB9A095621256F9FB523" },
            V { key: "7BD86E2B8DDBBF431130FDA8C5479C19", iv: "37A41E87", pad: true,
                pt: "1762579CF1E8E9C1F6C4A7A5C089AB992555740A9FD7D5CB681A07F9C042969F9EE3A8E0B9940CC0DB85A5558FFF5EFE8F21708117E459408C8B33D7E0F001B42D0807DDE0CADF9149B32E1931803C69BC09699ED11587B98968532D6035DFEB84F12787F8801DC442DE3864B63F0F0C4FCA1AD78763E218814D537877B13114D443953F58B5703BEBA45BF2DD2303495946DE951A0763200E0F06AA2DA44D90AD238F72",
                ct: "C1A48806D8F8A135B7A68636A21203D4A414AEEC663557BA029DB5665EB7BEB69A93E7812277279B501A8EB96EEC64E66874AE7EE33A80CD5D2C3C65B02BF125B989E6BB72BFBC6266A915EDFE05D12B967E8B5C29D37A8B5A4DEB0DB7CC32064EA95C802377C4C22AE5AECAE61EADB9062B8E88382A194ECEB7F08B211FA9E3B1A69D9B37C243D47C9AA56C969C3BA8E2ED668E83BC369CB5C423EBF9A226E7AF00721AFFEB7AE544C9BABD84E4EE3E" },
            V { key: "AACFB49A5ADFECE208EF3B5D4A091F30", iv: "D3FFFFFF", pad: true,
                pt: "4657CA45B993909F8992433B3B1B81181ED4A85F23851CBD112AC292369E6BEB93D0A58A3DAA82C9BA6A959E8F60BDB15E5C12740667EAC13B0C338ED1FE69EB2758A76A75F7DA7452DEA5B9EF7D2EB16C1034D98BF7E42CE6E44E3076F3F7BB01A97636B8533B67819E2127C130D1BDDE8222C1CA8F6030737B8391A8AAFD5FE6E9B84606F7F819D4CD58EDD5BD6AB6129051F4D136F1714946C33DCFAABED7A0C240D7778AB7E78A09EDFD37725AB610CD7E1758088DB0F846FCBF33BA492A0E",
                ct: "E55B18F8DF0546749E5637BDFB11460BAF0BAB9F8CF2D2344335BE43E4F624D434EA724407C9CCA1CB0719C0D508B2A79D9B2AD6552AF40412E1D835707542AFA91C764C32DBC18272C9E88BB2763974FF9C6AF1888459589FC4CF86157F311C3E96C252396FD0CA5E43F8746ABF6501A7141806A82B57BEB506EB9B6D0D6977C0F5859B4A5BB15484F350B6DB8ED144E3D9368B39E2295A180536D4AAC5D18002E277E9EF4D9E0D408CB0FE7D08F61292C2554E9AC18B1F94538E8904F66D2B7002231D3FB984365D4013061D963F63" },
            V { key: "814C137C933E88D96A69C849F43AD6EC", iv: "0DFFFFFF", pad: false, pt: "308EF7B3CFBFC2EEB62647397D8FF63D", ct: "B5D3F8560A4577820D2E839D8EF122A5" },
            V { key: "EE9FC566040C26D3268D47FE6602B4DF", iv: "FFFFFFFF", pad: true,  pt: "B0A5D3AF72356A90F86E29", ct: "38D1239AF8949B43101EF67CB1C6F211" },
            V { key: "DB2467238C4278C488B371684DC981FC", iv: "5A3705BD", pad: false, pt: "53DED4C9FB71BB70C2D8E992BF2A5790", ct: "77813088C92EE813F90A7F7FCC42F88C" },
            V { key: "C17CD03E3D85E5F0380F59F3B149DC9C", iv: "F2F53964", pad: true,  pt: "8BF1986A9B0CAD2C1E81B736F1CEF8E3", ct: "5AD8ACC4AF8AFD1F5A5E269D53B592DF3E9965397F2CE7005BF6AECE35D1D39D" },
            V { key: "90EC18C8BF78FB4C9FC9F1F3EDC6F08F", iv: "8845F9F4", pad: true,
                pt: "2A5AE4BB036B6BBF6AA029ED3812F64BCAD11BB93F589127AEABD4048BC278CB813A4EA067E4C586872E5B4F669A0DE6",
                ct: "0EBF6D014252EA52C077B67AA2BEFAD20847A449B450B8CB1FDC3649E2C20FAD168A0F40D8982FEB2FB1A8CDE5504A1BFD4BE3A732272E049ECD5B78BEE385F9" },
            V { key: "FD0C03A1318C45D2C8BD0D58966733A8", iv: "275D6CFE", pad: true,  pt: "31", ct: "A126BB809FBA89EA9F656104F449BED6" },
            V { key: "10FC41C1139DED067FBED69AF5F47CD7", iv: "AAD66DEF", pad: true,  pt: "0F22A828", ct: "D47A868705A125678D9B1B8FF67978B7" },
            V { key: "1D959B5A35D586FBFABAA961B4EA50C2", iv: "760948FF", pad: false,
                pt: "4A19B8E48ECB5E56A040FF9ABFA650AFDCB246BE46C8D746B705DA2AEF0EF7F5481F8B6D42152CDE035E490FC3DC4AA12D8932EB6052CF8241722C88F0336692490951A01BE36DC68667BBE77EC883DB",
                ct: "D9339BB44320E9A58113E928753A441C499E17B4289C7FA1ECF6F640C42618BE599A3C70E475325C3123FEA5E2C2B2C2E17046EA3610EBF3DD50FEC8EC131B9E52021A8A4B5826CD599C05C38E190358" },
            V { key: "BB38FD66DB0B95F54F092BD0E9A3EDCF", iv: "F7B7C5B9", pad: false, pt: "6B65F897E80379EF50CDB836FFB63E74", ct: "800B79783988A4B9C38B580DBD43B29F" },
            V { key: "5C5112B79CDDE37AECEFC602C95110B2", iv: "B24A6FA6", pad: true,  pt: "98D5", ct: "98B5D3CAE67A2AE3C05455E5EC5FBFEB" },
            V { key: "3498F80187442E5974927F8E827DABF8", iv: "3D7725FF", pad: true,  pt: "D7", ct: "CE6ECAEC9FBEAAF74C2AD5AFBE66B697" },
            V { key: "FDEA0C05BB450D4553F7C47A8423B73D", iv: "20CBE124", pad: true,  pt: "98192E1443BBEF6D306F678DC3487437", ct: "B473762E32201AD37E60A64945A7D3123912F4280283876BD1672F62062A9254" },
            V { key: "570079FCA0DC05C863E96473B8497B45", iv: "CAFFADF3", pad: true,  pt: "", ct: "B23F34E57538504915DDA4479CFCA3FE" },
            V { key: "17F248D6920799AFE75B6E4E3E1BBC14", iv: "FFFFFFFF", pad: true,
                pt: "9B8020184B707288E9BCF1D1E2CBC4D0ED0DF78CE4F1DFB18D5BB20E630B54B5CF43FE2EC74222DECB93D25774E0768B",
                ct: "8C8F3AB5C6863E45D1DE3DBEB1CFF992510ABB95B44188B71EEBAA3E86655BA9A3F59795337F7E2299AE771D3428EC7C01AAB4432B046526A9641FB580613CBD" },
            V { key: "B7E4F9E62A37DFAAA16F8BF0BD6325DE", iv: "683C01FF", pad: true,
                pt: "511E883CADE426577E126D8A9864548D58B73220686DF3EF37DED8BF20DC4EFB11768E8B1932DE0B970BA7CCFAB2693A7809B0F3B8F857E32B9904CE0C6736A2",
                ct: "AE43CEB7586F6BB2848C623E01E26CE2575CE57EC97AB064E498A5D0D8831399E7D40471B5F7E984F679E0D8183D831D4230679D24A21FA47F8D9E6775B16C08B5367247F68ABDD4E6CF6196213BFA1F" },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let lrp = Lrp::from_base_key(hex_array(v.key));
            let iv = hex_bytes(v.iv);
            let pt = hex_bytes(v.pt);
            let expected_ct = hex_bytes(v.ct);
            assert!(!expected_ct.is_empty(), "vector {i}: empty CT");

            // Pre-pad with ISO/IEC 9797-1 Method 2 for `pad=true` vectors.
            // The in-place methods don't handle padding themselves.
            let padded_pt: Vec<u8> = if v.pad {
                let mut p = pt.clone();
                p.push(0x80);
                while !p.len().is_multiple_of(16) {
                    p.push(0);
                }
                p
            } else {
                pt.clone()
            };
            {
                let mut buf = padded_pt.clone();
                let mut counter = iv.clone();
                lrp.lricb_encrypt_in_place(&mut counter, &mut buf)
                    .unwrap_or_else(|| panic!("encrypt_in_place vector {i} returned None"));
                assert_eq!(buf, expected_ct, "encrypt_in_place vector {i}");
            }
            {
                let mut buf = expected_ct.clone();
                let mut counter = iv;
                lrp.lricb_decrypt_in_place(&mut counter, &mut buf)
                    .unwrap_or_else(|| panic!("decrypt_in_place vector {i} returned None"));
                assert_eq!(buf, padded_pt, "decrypt_in_place vector {i}");
            }
        }
    }

    // Test vectors from NXP AN12304 §3.4. KEY is the base key (derives plaintexts
    // and k' = UK[0]); Kx is the CMAC subkey (K1 if message is a positive multiple
    // of 16 bytes, else K2). Both paths are exercised.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "AN12304 LRP-CMAC vectors; native CI already covers correctness"
    )]
    fn cmac_an12304_vectors() {
        use cmac::{Cmac, Mac, digest::InnerInit};

        // GF(2^128) "mul by x" per SP 800-38B, reduction polynomial x^128+x^7+x^2+x+1.
        fn dbl(b: &[u8; 16]) -> [u8; 16] {
            let msb = b[0] >> 7;
            let mut out = [0u8; 16];
            for i in 0..15 {
                out[i] = (b[i] << 1) | (b[i + 1] >> 7);
            }
            out[15] = b[15] << 1;
            if msb == 1 {
                out[15] ^= 0x87;
            }
            out
        }

        struct V {
            key: &'static str,
            kx: &'static str,
            msg: &'static str,
            mac: &'static str,
        }

        #[rustfmt::skip]
        let vectors = [
            // K2 path (padded last block).
            V { key: "E7FEB463C2498E04EFC5BF503473FC3A", kx: "EC31EA82E247DB1AAE486AE404C5D252",
                msg: "F3EFB6B0D4A7", mac: "C17AA38420EE2AA13087578CFBB0B7F3" },
            V { key: "7860B864632C6C8BC9A4C06D49D7E2AE", kx: "C3D55306E216D704D6FFDB120D56B990",
                msg: "DC7F", mac: "59D3D3A4307A3BBD8E8E5F4B8E75510D" },
            V { key: "E2F84A0B0AF40EFEB3EEA215A436605C", kx: "6843C8FDC5C7AEABDF473D186A42EDA3",
                msg: "8BF1DDA9FE445560A4F4EB9CE0", mac: "D04382DF71BC293FEC4BB10BDB13805F" },
            V { key: "A418BA1658A6F0D90830C58679F80AC4", kx: "43033791EEA9FF04B189958D562C6A5C",
                msg: "06", mac: "FF9561CC6E45FFFD4388003AA5F61233" },
            V { key: "AEA00AD0EF9243833DA4861D6A0D2C8C", kx: "50368F14FF9E0252897F46B2D4C92142",
                msg: "", mac: "954230A72692BAB4CE1A44473D081376" },
            V { key: "055A4CE2713D7D8B18EF014394D266A6", kx: "359AE1AA196387EC39F9E8E608FDC826",
                msg: "", mac: "8D8FDCF864C745DF8ABAAFADA00F5074" },
            V { key: "8F4EC0BE7A3F5B6A2AAA92814F454F70", kx: "0EE5492230A06FA5A2F89D767923B58D",
                msg: "6CB1DB9648E809AC7B0988B160B20BED144A648DB75E854E50A2CA0F8D5F13FE70FF229CE427315651BD",
                mac: "CFF39D67CB2B1987DDE2841E4C7F6225" },
            V { key: "01B823CA9E8EFE175836625AA152E972", kx: "A38CD6F22953DB258CB5ABBB508EF884",
                msg: "61", mac: "32A2D28599066AA0DDCD1DFB6C3373B0" },
            // K1 path (last block full, no padding).
            V { key: "DD65C1973AAE481556949A70BBA498A8", kx: "AD46B292A44636C9935DAC161263AB3C",
                msg: "DE3560AAC2D50387DBE216179395F41B",
                mac: "E19DA6375B7D44AC7EF2DC379E496775" },
            V { key: "7BB18459270EA38C4EB115EAE374FEA4", kx: "10CD915058439C89AE22B6CB9712804B",
                msg: "2927AE423C96C4BAA61E34BE46EE8436",
                mac: "B342A9697FC469EC29D554E24742936E" },
            V { key: "340567430897CFCEA4CEC0D2FBB84C58", kx: "2A22AC48EFA945339B22E335464B4B96",
                msg: "E5DEA257FC642D6A74D60187702BB635",
                mac: "B9A019E7BB4A84929365B6414D84B849" },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let lrp = Lrp::from_base_key(hex_array(v.key));
            let msg = hex_bytes(v.msg);

            let mut k0 = Block::default();
            BlockCipherEncrypt::encrypt_block(&lrp, &mut k0);
            let mut k0_arr = [0u8; 16];
            k0_arr.copy_from_slice(k0.as_slice());
            let k1 = dbl(&k0_arr);
            let k2 = dbl(&k1);
            let want_kx = if !msg.is_empty() && msg.len().is_multiple_of(16) {
                k1
            } else {
                k2
            };
            assert_eq!(want_kx, hex_array(v.kx), "vector {i}: Kx");

            let mut mac = Cmac::<Lrp>::inner_init(lrp);
            mac.update(&msg);
            let got = mac.finalize().into_bytes();
            assert_eq!(
                got.as_slice(),
                &hex_array::<16>(v.mac)[..],
                "vector {i}: MAC"
            );
        }
    }
}
