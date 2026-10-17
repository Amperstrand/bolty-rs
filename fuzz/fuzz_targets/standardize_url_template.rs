//! Fuzz the burn-side URL template normalizer:
//! `bolty_ntag::standardize_url_template` over arbitrary strings (#86 —
//! the rig feeds emulated-card URLs; the template path must survive any
//! byte sequence a hostile tag writes into the NDEF record).

#![no_main]

use bolty_ntag::standardize_url_template;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = standardize_url_template(s);
});
