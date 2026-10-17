#![no_main]
use libfuzzer_sys::fuzz_target;
use bolty_ntag::parse_ndef_uri;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ndef_uri(data);
});
