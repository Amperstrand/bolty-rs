//! Fuzz NDEF T4T parsing: `bolty_ntag::parse_ndef_uri` (#86: "CC-file
//! and NLEN parsing — offsets/sizes from hostile values"). Length lies
//! (NLEN vs actual), short/long records, ID-length fields, URI
//! identifier codes — all from raw bytes.

#![no_main]

use bolty_ntag::parse_ndef_uri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ndef_uri(data);
});
