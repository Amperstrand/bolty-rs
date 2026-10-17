//! Fuzz the full SUN read path: `picc_parse_url(k1, k2, url)` —
//! p/c extraction, AES decrypt, format-tag checks, CMAC verify (#86).
//! Input layout: k1 (16) || k2 (16) || URL bytes (lossy UTF-8).

#![no_main]

use bolty_core::picc::picc_parse_url;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let mut k1 = [0u8; 16];
    k1.copy_from_slice(&data[..16]);
    let mut k2 = [0u8; 16];
    k2.copy_from_slice(&data[16..32]);
    let url = String::from_utf8_lossy(&data[32..]);
    let _ = picc_parse_url(&k1, &k2, &url);
});
