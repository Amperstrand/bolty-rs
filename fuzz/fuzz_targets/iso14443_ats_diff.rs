#![no_main]
//! Differential: the Amperstrand fork's ATS parse vs canonical upstream's.
//! Divergence in accept/reject for the SAME wire bytes is drift; the crash
//! artifact carries both verdicts for triage.
use libfuzzer_sys::fuzz_target;
use iso14443_fork::type_a::Ats as ForkAts;
use iso14443_upstream::type_a::Ats as UpAts;

fn verdict_fork(d: &[u8]) -> bool {
    ForkAts::try_from(d).is_ok()
}
fn verdict_up(d: &[u8]) -> bool {
    // Same wire contract as the fork: on-the-air bytes WITH CRC, verified.
    // (A CRC-stripped fallback bridged the fork's pre-SFT-7605 semantics
    // and produced false drift on inputs like 01 01 01 — the fork and
    // upstream now share the parse code, so the contracts are identical.)
    UpAts::try_from(d).is_ok()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let f = verdict_fork(data);
    let u = verdict_up(data);
    if f != u {
        panic!(
            "ATS differential drift: fork={} upstream(on-air|stripped)={} input={:02x?}",
            f, u, data
        );
    }
});
