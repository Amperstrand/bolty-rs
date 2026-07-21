//! Dedicated security regression test suite for bolty-rs (issue #41).
//!
//! Modeled on the lnforward 12-domain pattern
//! (`hackathon-tooling/patterns/testing/security-test-suite.md`): each module
//! names one security domain and encodes its invariants as named, documented
//! regression tests. Every test asserts an externally observable security
//! contract, never an implementation detail.
//!
//! ## Scope
//!
//! This integration test binary verifies the security invariants exposed by the
//! **library** crates (`bolty-core`, `bolty-ntag`). The `bolty-cli` binary
//! crate is not importable from here (it has no `lib.rs`), so its security
//! invariants — the `burn` URL guard, the audit-log tag placement, the
//! diagnose state/provenance classifiers — are covered by inline
//! `#[cfg(test)] mod security_tests` modules in those source files. Together
//! the two layers form the complete regression suite.
//!
//! ## Domains
//!
//! | Module                       | Invariant                                                |
//! |------------------------------|----------------------------------------------------------|
//! | `key_zeroization`            | Secret key material is wiped on drop (`zeroize`).        |
//! | `debug_redaction`            | Secrets never appear in `Debug` output.                  |
//! | `audit_integrity`            | Provenance tags have a deterministic, parseable format.  |
//! | `url_validation`             | SDM URL templates require `{picc}`/`{mac}` placeholders. |
//! | `provenance_classification`  | The four key-provenance variants are distinct & total.   |
//! | `state_transition_guards`    | Card-state constants pin the valid lifecycle boundaries. |

// Integration test binaries are test-only: `unwrap`/`expect`/`panic` are the
// idiomatic assertion primitives. The workspace turns these into warnings, so
// silence them at the crate root.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod audit_integrity;
mod debug_redaction;
mod key_zeroization;
mod provenance_classification;
mod state_transition_guards;
mod url_validation;
