// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! SDM session key derivation and MAC verification (NT4H2421Gx §9.3.9).

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};

use crate::crypto::ct_eq_8;
use crate::crypto::lrp::{Lrp, generate_plaintexts, generate_updated_keys};
use crate::crypto::suite::{cmac_aes, cmac_lrp, truncate_mac};

#[cfg(feature = "alloc")]
pub(super) type LrpSessionState = Box<Lrp>;
#[cfg(not(feature = "alloc"))]
pub(super) type LrpSessionState = Lrp;

/// SDM session keys for both AES and LRP paths.
pub(super) enum SdmKeys {
    Aes {
        enc_key: [u8; 16],
        mac_key: [u8; 16],
    },
    Lrp {
        enc: LrpSessionState,
        mac: LrpSessionState,
    },
}

impl SdmKeys {
    /// Verify an SDMMAC with constant-time comparison.
    pub(super) fn verify_mac(&self, data: &[u8], expected: &[u8; 8]) -> bool {
        let computed = match self {
            Self::Aes { mac_key, .. } => truncate_mac(&cmac_aes(mac_key, data)),
            Self::Lrp { mac, .. } => truncate_mac(&cmac_lrp(Lrp::clone(mac), data)),
        };
        ct_eq_8(&computed, expected)
    }
}

/// Derive SDM session keys in AES mode (§9.3.9.1).
pub(super) fn derive_sdm_keys_aes(
    sdm_file_read_key: &[u8; 16],
    uid: Option<&[u8; 7]>,
    sdm_read_ctr: Option<&[u8; 3]>,
) -> SdmKeys {
    let build_sv = |label: [u8; 2]| -> [u8; 16] {
        let mut sv = [0u8; 16];
        sv[0..2].copy_from_slice(&label);
        sv[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
        let mut off = 6;
        if let Some(u) = uid {
            sv[off..off + 7].copy_from_slice(u);
            off += 7;
        }
        if let Some(c) = sdm_read_ctr {
            sv[off..off + 3].copy_from_slice(c);
        }
        sv
    };

    SdmKeys::Aes {
        enc_key: cmac_aes(sdm_file_read_key, &build_sv([0xC3, 0x3C])),
        mac_key: cmac_aes(sdm_file_read_key, &build_sv([0x3C, 0xC3])),
    }
}

/// Derive SDM session keys in LRP mode (§9.3.9.2).
///
/// `SV = 00 01 00 80 [|| UID] [|| SDMReadCtr] [|| ZeroPadding] || 1E E1`
pub(super) fn derive_sdm_keys_lrp(
    sdm_file_read_key: &[u8; 16],
    uid: Option<&[u8; 7]>,
    sdm_read_ctr: Option<&[u8; 3]>,
) -> SdmKeys {
    let mut sv = [0u8; 16];
    sv[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    let mut off = 4;
    if let Some(u) = uid {
        sv[off..off + 7].copy_from_slice(u);
        off += 7;
    }
    if let Some(c) = sdm_read_ctr {
        sv[off..off + 3].copy_from_slice(c);
    }
    // Zero-padding is implicit (array initialized to 0).
    sv[14..16].copy_from_slice(&[0x1E, 0xE1]);

    // SesSDMFileReadMasterKey = CMAC_LRP(SDMFileReadKey, SV)
    let kx_lrp = Lrp::from_base_key(*sdm_file_read_key);
    let master: [u8; 16] = cmac_lrp(kx_lrp, &sv);

    // SesSDMFileReadSPT, then UK[0] = MAC key, UK[1] = ENC key.
    let plaintexts = generate_plaintexts(master);
    let [uk_mac, uk_enc] = generate_updated_keys::<2>(master);

    SdmKeys::Lrp {
        mac: make_lrp_session_state(Lrp::from_parts(plaintexts, uk_mac)),
        enc: make_lrp_session_state(Lrp::from_parts(plaintexts, uk_enc)),
    }
}

#[cfg(feature = "alloc")]
fn make_lrp_session_state(lrp: Lrp) -> LrpSessionState {
    Box::new(lrp)
}

#[cfg(not(feature = "alloc"))]
fn make_lrp_session_state(lrp: Lrp) -> LrpSessionState {
    lrp
}

/// AES-128 ECB encrypt a single block.
pub(super) fn aes_ecb_encrypt_block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&Array::from(*key));
    let mut out = Array::default();
    cipher.encrypt_block_b2b(&Array::from(*input), &mut out);
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{aes_cbc_decrypt, aes_cbc_encrypt};
    use crate::testing::hex_array;

    // AN12196 §3.3, Table 1 - SDM session key derivation (AES).
    #[test]
    fn session_keys_an12196_t1() {
        let key = hex_array::<16>("5ACE7E50AB65D5D51FD5BF5A16B8205B");
        let uid = hex_array::<7>("04C767F2066180");
        let ctr = hex_array::<3>("010000");

        let keys = derive_sdm_keys_aes(&key, Some(&uid), Some(&ctr));
        match keys {
            SdmKeys::Aes { enc_key, mac_key } => {
                assert_eq!(enc_key, hex_array("66DA61797E23DECA5D8ECA13BBADF7A9"));
                assert_eq!(mac_key, hex_array("3A3E8110E05311F7A3FCF0D969BF2B48"));
            }
            _ => unreachable!(),
        }
    }

    // AN12196 §3.4.3.2, Table 3 - SDMENCFileData decryption (AES).
    #[test]
    fn enc_file_data_an12196_t3() {
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("010000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let enc_key = match &keys {
            SdmKeys::Aes { enc_key, .. } => *enc_key,
            _ => unreachable!(),
        };
        assert_eq!(enc_key, hex_array("8097D73344D53F963B09E23E03B62336"));

        // IV = AES-ECB-ENC(ENCKey, SDMReadCtr || 0^13)
        let mut iv_in = [0u8; 16];
        iv_in[..3].copy_from_slice(&ctr);
        let iv = aes_ecb_encrypt_block(&enc_key, &iv_in);
        assert_eq!(iv, hex_array("7B3F3CFC39D3B7FF5868636E38AF7C3A"));

        let mut ct = hex_array::<16>("94592FDE69FA06E8E3B6CA686A22842B");
        aes_cbc_decrypt(&enc_key, &iv, &mut ct).unwrap();
        // 16 bytes of ASCII 'x' (0x78)
        assert_eq!(&ct, b"xxxxxxxxxxxxxxxx");
    }

    // AN12196 §3.4.4.2.1, Table 4 - SDMMAC with empty input.
    #[test]
    fn mac_empty_an12196_t4() {
        let uid = hex_array::<7>("04DE5F1EACC040");
        let ctr = hex_array::<3>("3D0000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        assert_eq!(mac_key, hex_array("3FB5F6E3A807A03D5E3570ACE393776F"));
        assert!(keys.verify_mac(b"", &hex_array("94EED9EE65337086")));
    }

    // AN12196 §3.4.4.2.2, Table 5 - SDMMAC with non-empty input.
    #[test]
    fn mac_nonempty_an12196_t5() {
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("080000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        assert_eq!(mac_key, hex_array("3ED0920E5E6A0320D823D5987FEAFBB1"));
        assert!(keys.verify_mac(
            b"CEE9A53E3E463EF1F459635736738962&cmac=",
            &hex_array("ECC1E7F6C6C73BF6"),
        ));
    }

    /// LRP session key derivation - intermediate master key check.
    #[test]
    fn lrp_session_key_master_derivation() {
        // From test_lrp_sdm.py: key=0, UID=042E1D222A6380, ctr=6A0000
        let key = [0u8; 16];
        let uid = hex_array::<7>("042E1D222A6380");
        let ctr = hex_array::<3>("6A0000");

        use crate::crypto::lrp::Lrp;
        use crate::crypto::suite::cmac_lrp;

        let mut sv = [0u8; 16];
        sv[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
        sv[4..11].copy_from_slice(&uid);
        sv[11..14].copy_from_slice(&ctr);
        sv[14..16].copy_from_slice(&[0x1E, 0xE1]);

        let master = cmac_lrp(Lrp::from_base_key(key), &sv);
        assert_eq!(master, hex_array("99C2FD9C885C2CA3C9089C20057310C0"));

        let keys = derive_sdm_keys_lrp(&key, Some(&uid), Some(&ctr));
        assert!(matches!(keys, SdmKeys::Lrp { .. }));
    }

    // Suppress unused import warning when alloc feature is not enabled.
    #[allow(unused_imports)]
    use aes_cbc_encrypt as _;
}
