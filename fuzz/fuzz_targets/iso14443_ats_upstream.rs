#![no_main]
use libfuzzer_sys::fuzz_target;
use iso14443_upstream::type_a::Ats;

fuzz_target!(|data: &[u8]| {
    // both entry points: the CRC-verified form and the off-the-air form
    let _ = Ats::from_crc_verified(data);
    let _ = Ats::try_from(data);
});
