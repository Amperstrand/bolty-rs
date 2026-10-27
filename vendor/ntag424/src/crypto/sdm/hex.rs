// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! ASCII-hex decoding helpers for NDEF SDM placeholder fields.

use super::verifier::SdmError;

fn hex_nibble(b: u8, offset: usize) -> Result<u8, SdmError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(SdmError::InvalidHex { offset }),
    }
}

pub(super) fn decode_hex_array<const N: usize>(
    data: &[u8],
    offset: usize,
) -> Result<[u8; N], SdmError> {
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(data[offset + 2 * i], offset + 2 * i)?;
        let lo = hex_nibble(data[offset + 2 * i + 1], offset + 2 * i + 1)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

pub(super) fn decode_hex_into(out: &mut [u8], data: &[u8], offset: usize) -> Result<(), SdmError> {
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(data[offset + 2 * i], offset + 2 * i)?;
        let lo = hex_nibble(data[offset + 2 * i + 1], offset + 2 * i + 1)?;
        *byte = (hi << 4) | lo;
    }
    Ok(())
}

pub(super) fn ensure_len(data: &[u8], needed: usize) -> Result<(), SdmError> {
    if data.len() < needed {
        Err(SdmError::NdefTooShort {
            needed,
            have: data.len(),
        })
    } else {
        Ok(())
    }
}
