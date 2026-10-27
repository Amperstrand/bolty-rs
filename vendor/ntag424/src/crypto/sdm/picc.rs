// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! PICCData decryption (NT4H2421Gx §9.3.4).

use super::verifier::SdmError;
use crate::crypto::lrp::Lrp;
use crate::crypto::suite::aes_cbc_decrypt_n;

/// Decrypted PICCData fields extracted from the NDEF file.
pub(super) struct ParsedPiccData {
    pub(super) uid: Option<[u8; 7]>,
    pub(super) read_ctr: Option<[u8; 3]>,
}

/// Parse the `PICCDataTag` byte and extract UID / SDMReadCtr from
/// a 16-byte decrypted PICCData block (shared between AES and LRP, §9.3.4).
fn parse_picc_data_tag(plain: &[u8; 16]) -> Result<ParsedPiccData, SdmError> {
    let tag = plain[0];
    let uid_present = tag & 0x80 != 0;
    let ctr_present = tag & 0x40 != 0;
    let uid_len = (tag & 0x0F) as usize;

    if uid_present && uid_len != 7 {
        return Err(SdmError::InvalidPiccDataTag(tag));
    }

    let mut off = 1;
    let uid = if uid_present {
        let mut u = [0u8; 7];
        u.copy_from_slice(&plain[off..off + 7]);
        off += 7;
        Some(u)
    } else {
        None
    };

    let read_ctr = if ctr_present {
        let mut c = [0u8; 3];
        c.copy_from_slice(&plain[off..off + 3]);
        Some(c)
    } else {
        None
    };

    Ok(ParsedPiccData { uid, read_ctr })
}

/// Decrypt AES-encrypted PICCData (§9.3.4.1).
pub(super) fn decrypt_picc_data_aes(
    key: &[u8; 16],
    enc: &[u8; 16],
) -> Result<ParsedPiccData, SdmError> {
    let mut plain = *enc;
    aes_cbc_decrypt_n(key, &[0u8; 16], &mut plain);
    parse_picc_data_tag(&plain)
}

/// Decrypt LRP-encrypted PICCData (§9.3.4.2).
///
/// Wire format: `PICCRand (8 bytes) || LRICB ciphertext (16 bytes)`.
pub(super) fn decrypt_picc_data_lrp(
    key: &[u8; 16],
    wire: &[u8; 24],
) -> Result<ParsedPiccData, SdmError> {
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&wire[..8]);
    let mut plain = [0u8; 16];
    plain.copy_from_slice(&wire[8..24]);

    let lrp = Lrp::from_base_key(*key);
    lrp.lricb_decrypt_in_place(&mut counter, &mut plain)
        .ok_or(SdmError::InvalidConfiguration(
            "PICCData LRICB decryption failed",
        ))?;

    parse_picc_data_tag(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex_array;

    // AN12196 §3.4.2.2, Table 2 - PICCData decryption (AES).
    #[test]
    fn picc_data_an12196_t2() {
        let enc = hex_array::<16>("EF963FF7828658A599F3041510671E88");
        let picc = decrypt_picc_data_aes(&[0u8; 16], &enc).unwrap();
        assert_eq!(picc.uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(picc.read_ctr, Some(hex_array("3D0000")));
    }

    #[test]
    fn lrp_picc_data_decryption() {
        let key = [0u8; 16];
        let wire = hex_array::<24>("AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293");
        let picc = decrypt_picc_data_lrp(&key, &wire).unwrap();
        assert_eq!(picc.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(picc.read_ctr, Some(hex_array("6A0000")));
    }
}
