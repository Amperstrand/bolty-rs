pub fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn decode_hex_into(hex: &str, out: &mut [u8]) -> Option<()> {
    if hex.len() != out.len() * 2 {
        return None;
    }
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Some(())
}

pub fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    decode_hex_into(hex, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode_hex, decode_hex_into, decode_hex_nibble};

    // ── decode_hex_nibble ──────────────────────────────────────────

    #[test]
    fn nibble_valid_digits() {
        assert_eq!(decode_hex_nibble(b'0'), Some(0));
        assert_eq!(decode_hex_nibble(b'9'), Some(9));
        for (ch, expected) in [(b'0', 0), (b'1', 1), (b'5', 5), (b'9', 9)] {
            assert_eq!(decode_hex_nibble(ch), Some(expected));
        }
    }

    #[test]
    fn nibble_valid_lowercase() {
        for (ch, expected) in [(b'a', 10), (b'b', 11), (b'c', 12), (b'd', 13), (b'e', 14), (b'f', 15)] {
            assert_eq!(decode_hex_nibble(ch), Some(expected));
        }
    }

    #[test]
    fn nibble_valid_uppercase() {
        for (ch, expected) in [(b'A', 10), (b'B', 11), (b'C', 12), (b'D', 13), (b'E', 14), (b'F', 15)] {
            assert_eq!(decode_hex_nibble(ch), Some(expected));
        }
    }

    #[test]
    fn nibble_invalid_chars() {
        assert_eq!(decode_hex_nibble(b'g'), None);
        assert_eq!(decode_hex_nibble(b'G'), None);
        assert_eq!(decode_hex_nibble(b'z'), None);
        assert_eq!(decode_hex_nibble(b'Z'), None);
        assert_eq!(decode_hex_nibble(b' '), None);
        assert_eq!(decode_hex_nibble(b'-'), None);
        assert_eq!(decode_hex_nibble(b'\n'), None);
        assert_eq!(decode_hex_nibble(b'\0'), None);
        assert_eq!(decode_hex_nibble(0xFF), None);
    }

    #[test]
    fn nibble_boundaries() {
        assert_eq!(decode_hex_nibble(0x2F), None);
        assert_eq!(decode_hex_nibble(b'0'), Some(0));
        assert_eq!(decode_hex_nibble(b'9'), Some(9));
        assert_eq!(decode_hex_nibble(0x3A), None);
        assert_eq!(decode_hex_nibble(0x40), None);
        assert_eq!(decode_hex_nibble(b'A'), Some(10));
        assert_eq!(decode_hex_nibble(b'F'), Some(15));
        assert_eq!(decode_hex_nibble(0x47), None);
        assert_eq!(decode_hex_nibble(0x60), None);
        assert_eq!(decode_hex_nibble(b'a'), Some(10));
        assert_eq!(decode_hex_nibble(b'f'), Some(15));
        assert_eq!(decode_hex_nibble(0x67), None);
    }

    // ── decode_hex_into ────────────────────────────────────────────

    #[test]
    fn decode_into_valid_2_bytes() {
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("dead", &mut out), Some(()));
        assert_eq!(out, [0xDE, 0xAD]);
    }

    #[test]
    fn decode_into_valid_mixed_case() {
        let mut out = [0u8; 4];
        assert_eq!(decode_hex_into("DeAdBeef", &mut out), Some(()));
        assert_eq!(out, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_into_valid_all_zeros() {
        let mut out = [0u8; 16];
        assert_eq!(decode_hex_into("00000000000000000000000000000000", &mut out), Some(()));
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn decode_into_empty_string_empty_buf() {
        let mut out: [u8; 0] = [];
        assert_eq!(decode_hex_into("", &mut out), Some(()));
    }

    #[test]
    fn decode_into_wrong_length_too_short() {
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("de", &mut out), None);
    }

    #[test]
    fn decode_into_wrong_length_too_long() {
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("deadbe", &mut out), None);
    }

    #[test]
    fn decode_into_invalid_char_at_start() {
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("gead", &mut out), None);
    }

    #[test]
    fn decode_into_invalid_char_in_middle() {
        let mut out = [0u8; 4];
        assert_eq!(decode_hex_into("deXXbeef", &mut out), None);
    }

    #[test]
    fn decode_into_invalid_char_at_end() {
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("dexg", &mut out), None);
    }

    // ── decode_hex::<N> ────────────────────────────────────────────

    #[test]
    fn decode_hex_n7_valid() {
        let result: Option<[u8; 7]> = decode_hex("04a39493cc8680");
        assert_eq!(result, Some([0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80]));
    }

    #[test]
    fn decode_hex_n16_valid() {
        let result: Option<[u8; 16]> = decode_hex("00000000000000000000000000000001");
        assert_eq!(result, Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn decode_hex_n0_empty() {
        let result: Option<[u8; 0]> = decode_hex("");
        assert_eq!(result, Some([]));
    }

    #[test]
    fn decode_hex_wrong_length() {
        let result: Option<[u8; 16]> = decode_hex("0001");
        assert_eq!(result, None);
    }

    #[test]
    fn decode_hex_invalid_chars() {
        let result: Option<[u8; 7]> = decode_hex("04g39493cc8680");
        assert_eq!(result, None);
    }

    #[test]
    fn decode_hex_uppercase_works() {
        let result: Option<[u8; 4]> = decode_hex("DEADBEEF");
        assert_eq!(result, Some([0xDE, 0xAD, 0xBE, 0xEF]));
    }
}
