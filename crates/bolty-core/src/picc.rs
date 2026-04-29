use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use cmac::{Cmac, Mac};

pub const PICC_FORMAT_BOLTCARD: u8 = 0xC7;
pub const PICC_FLAG_HAS_UID: u8 = 0x80;
pub const PICC_FLAG_HAS_COUNTER: u8 = 0x40;
pub const PICC_UID_BYTE_LEN: usize = 7;
pub const PICC_COUNTER_LEN: usize = 3;
pub const SV2_HEADER: [u8; 6] = [0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80];

type Aes128CbcDec = cbc::Decryptor<Aes128>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PiccData {
    pub valid: bool,
    pub uid: [u8; 7],
    pub counter: u32,
    pub has_uid: bool,
    pub has_counter: bool,
}

pub fn extract_p_and_c(url: &str) -> Option<(&str, &str)> {
    let mut p = None;
    let mut c = None;

    let mut start = 0;
    for (idx, ch) in url.char_indices() {
        if matches!(ch, '?' | '&' | '#') {
            parse_param(&url[start..idx], &mut p, &mut c);
            start = idx + ch.len_utf8();
        }
    }
    parse_param(&url[start..], &mut p, &mut c);

    match (p, c) {
        (Some(p_hex), Some(c_hex)) => Some((p_hex, c_hex)),
        _ => None,
    }
}

pub fn picc_decrypt_p(k1: &[u8; 16], p_hex: &str) -> Option<PiccData> {
    if p_hex.len() != 32 {
        return None;
    }

    let mut ciphertext = [0u8; 16];
    decode_hex_into(p_hex, &mut ciphertext)?;

    let iv = [0u8; 16];
    let mut decrypted = ciphertext;
    Aes128CbcDec::new(k1.into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut decrypted)
        .ok()?;

    if decrypted[0] != PICC_FORMAT_BOLTCARD {
        return None;
    }

    if (decrypted[0] & PICC_FLAG_HAS_UID) == 0
        || (decrypted[0] & PICC_FLAG_HAS_COUNTER) == 0
        || usize::from(decrypted[0] & 0x07) != PICC_UID_BYTE_LEN
    {
        return None;
    }

    let mut picc = PiccData {
        has_uid: true,
        has_counter: true,
        ..PiccData::default()
    };

    picc.uid.copy_from_slice(&decrypted[1..1 + PICC_UID_BYTE_LEN]);
    picc.counter = u32::from(decrypted[8])
        | (u32::from(decrypted[9]) << 8)
        | (u32::from(decrypted[10]) << 16);

    Some(picc)
}

pub fn sdm_build_sv2(uid: &[u8; 7], counter: u32) -> [u8; 16] {
    let mut sv2 = [0u8; 16];
    sv2[..SV2_HEADER.len()].copy_from_slice(&SV2_HEADER);
    sv2[6..13].copy_from_slice(uid);
    sv2[13] = counter as u8;
    sv2[14] = (counter >> 8) as u8;
    sv2[15] = (counter >> 16) as u8;
    sv2
}

pub fn picc_verify_c(k2: &[u8; 16], picc: &PiccData, c_hex: &str) -> bool {
    if !picc.has_uid || !picc.has_counter || c_hex.len() != 16 {
        return false;
    }

    let mut expected = [0u8; 8];
    if decode_hex_into(c_hex, &mut expected).is_none() {
        return false;
    }

    let sv2 = sdm_build_sv2(&picc.uid, picc.counter);
    let derived_key = cmac_aes128(k2, &sv2);
    let full_mac = cmac_aes128(&derived_key, &[]);
    let computed = truncate_odd_bytes(&full_mac);

    constant_time_eq(&computed, &expected)
}

pub fn picc_parse_url(k1: &[u8; 16], k2: &[u8; 16], url: &str) -> PiccData {
    let Some((p_hex, c_hex)) = extract_p_and_c(url) else {
        return PiccData::default();
    };

    let Some(mut picc) = picc_decrypt_p(k1, p_hex) else {
        return PiccData::default();
    };

    if !picc_verify_c(k2, &picc, c_hex) {
        return PiccData::default();
    }

    picc.valid = true;
    picc
}

fn parse_param<'a>(segment: &'a str, p: &mut Option<&'a str>, c: &mut Option<&'a str>) {
    if let Some(value) = segment.strip_prefix("p=") {
        *p = Some(value);
    } else if let Some(value) = segment.strip_prefix("c=") {
        *c = Some(value);
    }
}

fn decode_hex_into<const N: usize>(hex: &str, out: &mut [u8; N]) -> Option<()> {
    if hex.len() != N * 2 {
        return None;
    }

    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }

    Some(())
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn cmac_aes128(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let Ok(mut mac) = Cmac::<Aes128>::new_from_slice(key) else {
        return [0u8; 16];
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn truncate_odd_bytes(full_mac: &[u8; 16]) -> [u8; 8] {
    core::array::from_fn(|idx| full_mac[idx * 2 + 1])
}

fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for (&lhs, &rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;
    use cbc::Encryptor;

    const FIXTURE_FILE: &str = include_str!("../../../tests/fixtures/picc/valid_picc.toml");
    const K1: [u8; 16] = [
        0x55, 0xDA, 0x17, 0x4C, 0x96, 0x08, 0x99, 0x3D, 0xC2, 0x7B, 0xB3, 0xF3, 0x0A, 0x4A,
        0x73, 0x14,
    ];
    const K2: [u8; 16] = [
        0x2A, 0xB7, 0x4A, 0xBC, 0x12, 0x73, 0xFB, 0x43, 0xCA, 0xE9, 0x75, 0x53, 0xA3, 0x6D,
        0x4D, 0x08,
    ];

    #[test]
    fn picc_valid_vectors() {
        assert!(FIXTURE_FILE.contains("E61CB056F52D34F9368F079D1814D2CF"));

        let fixture_url = "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298";
        let fixture_picc = picc_parse_url(&K1, &K2, fixture_url);
        assert!(fixture_picc.valid);
        assert_eq!(fixture_picc.uid, [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80]);
        assert_eq!(fixture_picc.counter, 0);
        assert!(fixture_picc.has_uid);
        assert!(fixture_picc.has_counter);

        let manual_picc = PiccData {
            valid: false,
            uid: [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80],
            counter: 42,
            has_uid: true,
            has_counter: true,
        };
        let sv2 = sdm_build_sv2(&manual_picc.uid, manual_picc.counter);
        assert_eq!(sv2, [0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80, 0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80, 0x2A, 0x00, 0x00]);

        let derived_key = cmac_aes128(&K2, &sv2);
        let mac_hex = hex_string(&truncate_odd_bytes(&cmac_aes128(&derived_key, &[])));
        assert!(picc_verify_c(&K2, &manual_picc, &mac_hex));

        let p_hex = encrypt_p_hex(&K1, &manual_picc);
        let url = build_url(&p_hex, &mac_hex);
        let parsed = picc_parse_url(&K1, &K2, &url);
        assert!(parsed.valid);
        assert_eq!(parsed.uid, manual_picc.uid);
        assert_eq!(parsed.counter, manual_picc.counter);
        assert!(extract_p_and_c(&url).is_some());
        assert_eq!(picc_decrypt_p(&K1, p_hex.as_str()), Some(manual_picc));
    }

    #[test]
    fn picc_invalid_inputs() {
        let valid_picc = PiccData {
            valid: false,
            uid: [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80],
            counter: 1,
            has_uid: true,
            has_counter: true,
        };
        let p_hex = encrypt_p_hex(&K1, &valid_picc);
        let derived_key = cmac_aes128(&K2, &sdm_build_sv2(&valid_picc.uid, valid_picc.counter));
        let mac_hex = hex_string(&truncate_odd_bytes(&cmac_aes128(&derived_key, &[])));

        assert!(!picc_parse_url(&K1, &K2, "https://example.com/bolt?c=0011223344556677").valid);
        assert!(!picc_parse_url(&K1, &K2, "https://example.com/bolt?p=00112233445566778899AABBCCDDEEFF").valid);
        assert!(!picc_parse_url(&K1, &K2, "https://example.com/bolt?p=ZZ112233445566778899AABBCCDDEEFF&c=0011223344556677").valid);
        assert!(!picc_parse_url(&K1, &K2, "https://example.com/bolt?p=00112233445566778899AABBCCDDEE&c=0011223344556677").valid);
        assert!(picc_decrypt_p(&[0u8; 16], p_hex.as_str()).is_none());
        assert!(!picc_parse_url(&K1, &K2, &build_url(&p_hex, "0011223344556677")).valid);
        assert!(picc_parse_url(&K1, &K2, &build_url(&p_hex, &mac_hex)).valid);
        assert!(!picc_parse_url(&[0u8; 16], &K2, &build_url(&p_hex, &mac_hex)).valid);
    }

    fn encrypt_p_hex(key: &[u8; 16], picc: &PiccData) -> heapless::String<32> {
        let mut plaintext = [0u8; 16];
        plaintext[0] = PICC_FORMAT_BOLTCARD;
        plaintext[1..8].copy_from_slice(&picc.uid);
        plaintext[8] = picc.counter as u8;
        plaintext[9] = (picc.counter >> 8) as u8;
        plaintext[10] = (picc.counter >> 16) as u8;

        let iv = [0u8; 16];
        let mut ciphertext = plaintext;
        assert!(
            Encryptor::<Aes128>::new(key.into(), (&iv).into())
                .encrypt_padded_mut::<NoPadding>(&mut ciphertext, plaintext.len())
                .is_ok()
        );

        hex_string_16(&ciphertext)
    }

    fn build_url(p_hex: &str, c_hex: &str) -> heapless::String<128> {
        let mut url = heapless::String::<128>::new();
        url.push_str("https://example.com/bolt?c=").unwrap();
        url.push_str(c_hex).unwrap();
        url.push_str("&p=").unwrap();
        url.push_str(p_hex).unwrap();
        url
    }

    fn hex_string(bytes: &[u8; 8]) -> heapless::String<16> {
        let mut out = heapless::String::<16>::new();
        for byte in bytes {
            assert!(out.push(nybble_to_hex(byte >> 4)).is_ok());
            assert!(out.push(nybble_to_hex(byte & 0x0F)).is_ok());
        }
        out
    }

    fn hex_string_16(bytes: &[u8; 16]) -> heapless::String<32> {
        let mut out = heapless::String::<32>::new();
        for byte in bytes {
            assert!(out.push(nybble_to_hex(byte >> 4)).is_ok());
            assert!(out.push(nybble_to_hex(byte & 0x0F)).is_ok());
        }
        out
    }

    fn nybble_to_hex(nybble: u8) -> char {
        match nybble {
            0..=9 => char::from(b'0' + nybble),
            10..=15 => char::from(b'A' + (nybble - 10)),
            _ => unreachable!(),
        }
    }
}
