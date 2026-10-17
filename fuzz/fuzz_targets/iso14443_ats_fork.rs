#![no_main]
use libfuzzer_sys::fuzz_target;
use iso14443_fork::type_a::Ats;

fuzz_target!(|data: &[u8]| {
    let _ = Ats::try_from(data);
});
