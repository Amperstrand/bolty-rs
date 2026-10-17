#![no_main]
use libfuzzer_sys::fuzz_target;
use bolty_core::picc::{picc_parse_url, picc_decrypt_p};

// Fixed zero keys: the fuzz surface is the URL/PICC *parsing* path, not key
// material. exercise extract_p_and_c / parse_param / hex decode / AES unwrap
// error paths with hostile URLs and hostile PICC hex strings.
fuzz_target!(|data: &[u8]| {
    let url = String::from_utf8_lossy(data);
    let _ = picc_parse_url(&[0u8; 16], &[0u8; 16], &url);
    // second byte onward as a PICC hex blob (first byte gates length use)
    if data.len() > 1 {
        let hex = String::from_utf8_lossy(&data[1..]);
        let _ = picc_decrypt_p(&[0u8; 16], &hex);
    }
});
