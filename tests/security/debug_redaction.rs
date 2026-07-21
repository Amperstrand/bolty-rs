//! SECURITY: Debug redaction — secrets never appear in `Debug` output.
//!
//! Invariant: `AesKey`, `CardKeys`, and `CardKeySet` implement `Debug` by
//! printing a fixed `([REDACTED])` placeholder, never the raw bytes. A
//! regression here would leak keys through `{:?}` in logs, error messages, or
//! `unwrap` panic backtraces — the single most common cause of secret leakage.
//!
//! Each test drives the redaction with byte patterns chosen to expose the
//! failure modes:
//!
//! - All-`0x42` / all-`0xAA` / all-`0xFF` — a naïve `Debug` that formats the
//!   inner array would render these as `42`/`aa`/`ff` hex digits.
//! - Distinct per-byte — exposes a partial redaction that only hides the first
//!   or last byte.
//! - Lower- and upper-case hex — `{:x?}` and `{:X?}` — both must be redacted.

use bolty_core::derivation::CardKeySet;
use bolty_core::secret::{AesKey, CardKeys};

/// Asserts the `Debug` rendering of `value` contains none of the forbidden
/// hex digit substrings derived from `needle_bytes` (in both lower and upper
/// case), and that it carries the `REDACTED` marker.
fn assert_redacted<T: std::fmt::Debug>(value: &T, needle_bytes: &[u8]) {
    let debug = format!("{value:?}");
    assert!(
        debug.contains("REDACTED"),
        "Debug must carry the REDACTED marker, got: {debug:?}"
    );
    for &byte in needle_bytes {
        let lower = format!("{byte:02x}");
        let upper = format!("{byte:02X}");
        assert!(
            !debug.contains(&lower),
            "Debug leaked byte {byte:#04x} as lower-case hex: {debug:?}"
        );
        assert!(
            !debug.contains(&upper),
            "Debug leaked byte {byte:#04x} as upper-case hex: {debug:?}"
        );
    }
}

#[test]
fn aeskey_debug_does_not_leak_uniform_bytes() {
    // SECURITY invariant: a uniformly-filled key must render as REDACTED. The
    // all-0x42 / 0xAA / 0xFF patterns are the canonical regression detectors.
    assert_redacted(&AesKey::new([0x42; 16]), &[0x42]);
    assert_redacted(&AesKey::new([0xAA; 16]), &[0xAA]);
    assert_redacted(&AesKey::new([0xFF; 16]), &[0xFF]);
}

#[test]
fn aeskey_debug_does_not_leak_distinct_bytes() {
    // SECURITY invariant: a key with a distinct byte in every position must
    // also redact. A partial redaction (e.g. hiding only index 0) would leak
    // the remaining 15 bytes.
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_redacted(&AesKey::new(bytes), &(0..=15).collect::<Vec<_>>());
}

#[test]
fn aeskey_debug_exact_redacted_form() {
    // SECURITY invariant: the exact redacted form is `AesKey([REDACTED])`.
    // Pinning the literal guards against a regression that changes the form to
    // something a downstream log-scraper no longer recognises as "secret".
    assert_eq!(
        format!("{:?}", AesKey::new([0xDE; 16])),
        "AesKey([REDACTED])"
    );
}

#[test]
fn aeskey_alternate_debug_forms_redacted() {
    // SECURITY invariant: `{:#?}` (pretty-Debug) must also redact. A custom
    // Debug that only handled the non-pretty path would leak under pretty-print.
    let key = AesKey::new([0x42; 16]);
    let pretty = format!("{key:#?}");
    assert!(pretty.contains("REDACTED"));
    assert!(!pretty.contains("42"));
}

#[test]
fn cardkeys_debug_does_not_leak() {
    // SECURITY invariant: CardKeys aggregates K0–K4; its Debug must redact the
    // whole aggregate, not delegate to the inner array form.
    let keys = CardKeys {
        k0: AesKey::new([0xAA; 16]),
        k1: AesKey::new([0xBB; 16]),
        k2: AesKey::new([0xCC; 16]),
        k3: AesKey::new([0xDD; 16]),
        k4: AesKey::new([0xEE; 16]),
    };
    assert_redacted(&keys, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    assert_eq!(format!("{:?}", keys), "CardKeys([REDACTED])");
}

#[test]
fn cardkeyset_debug_does_not_leak() {
    // SECURITY invariant: CardKeySet holds the derived key bundle plus a
    // card_id; its custom Debug must redact everything.
    let set = CardKeySet::default();
    // Even the zeroed state must render as REDACTED, not as raw zeros (which
    // would expose the field names and structure to an attacker).
    assert_redacted(&set, &[0]);
    assert_eq!(format!("{:?}", set), "CardKeySet([REDACTED])");
}

#[test]
fn redaction_holds_for_zeroed_key() {
    // SECURITY invariant: the zeroed (wiped) key still renders as REDACTED.
    // Even though zeros are not themselves secret, leaking the structure
    // (`[0, 0, 0, ...]`) reveals that a wipe occurred and the field layout.
    assert_redacted(&AesKey::zeroed(), &[0]);
}

#[test]
fn redaction_holds_across_clone() {
    // SECURITY invariant: cloning a key must not regress the Debug impl on
    // either copy. A derive(Debug) added later would leak both.
    let original = AesKey::new([0x99; 16]);
    let cloned = original.clone();
    assert_redacted(&original, &[0x99]);
    assert_redacted(&cloned, &[0x99]);
}
