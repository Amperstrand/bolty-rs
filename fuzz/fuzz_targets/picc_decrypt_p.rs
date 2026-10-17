//! Fuzz the SUN encrypted-part consumption: `picc_decrypt_p` (#86:
//! "malformed CMACs, truncated PICC data, length lies"). The fuzzer's
//! raw bytes are hex-encoded in-target so every execution reaches the
//! decrypt + PICCDataTag decode path instead of dying at hex validation.

#![no_main]

use bolty_core::picc::picc_decrypt_p;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut k1 = [0u8; 16];
    k1.copy_from_slice(&data[..16]);

    // Re-encode arbitrary cipher bytes as valid hex: deep coverage of the
    // decrypt/format-tag path without hoping the mutator discovers
    // 32-char hex strings on its own.
    let hex: String = data[16..32].iter().map(|b| format!("{b:02X}")).collect();
    let _ = picc_decrypt_p(&k1, &hex);

    // Also exercise the raw-string surface (length lies, non-hex chars).
    if let Ok(raw) = core::str::from_utf8(&data[16..]) {
        let _ = picc_decrypt_p(&k1, raw);
    }
});
