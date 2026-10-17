//! Fuzz the SUN authentication consumption: `picc_verify_c` — the CMAC
//! check over SV2 (uid || counter) against the `c=` parameter (#86).
//! Chains the real path: fuzzer cipher bytes → `picc_decrypt_p` →
//! PiccData → CMAC verify with fuzzer mac bytes (hex-encoded).

#![no_main]

use bolty_core::picc::{picc_decrypt_p, picc_verify_c};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 56 {
        return;
    }
    let mut k1 = [0u8; 16];
    k1.copy_from_slice(&data[..16]);
    let mut k2 = [0u8; 16];
    k2.copy_from_slice(&data[16..32]);

    let hex: String = data[32..48].iter().map(|b| format!("{b:02X}")).collect();
    let Some(picc) = picc_decrypt_p(&k1, &hex) else {
        return;
    };

    let mac_hex: String = data[48..56].iter().map(|b| format!("{b:02X}")).collect();
    let _ = picc_verify_c(&k2, &picc, &mac_hex);
});
