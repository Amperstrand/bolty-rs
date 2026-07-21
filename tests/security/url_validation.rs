//! SECURITY: URL validation — SDM URL templates require the `{picc}` and
//! `{mac}` placeholders.
//!
//! Invariant: a burnable Bolt Card URL must carry the `{picc}` and `{mac}`
//! SDM placeholders so the server can decrypt the card UID/counter and verify
//! the CMAC. Burning a URL without them produces a card that taps but can
//! never be verified — a silent brick.
//!
//! The runtime guard lives in `bolty-cli/src/burn.rs` (cmd_burn checks
//! `url.contains("{picc")` and `url.contains("{mac}")` before any card write,
//! with `--force` as the documented escape hatch). That guard is verified
//! inline in `burn.rs::security_tests`. This module verifies the
//! *library-level* URL contract: `standardize_url_template` must correctly
//! place the `[[` MAC delimiter without dropping or altering the placeholders.

use bolty_ntag::standardize_url_template;

#[test]
fn standardize_inserts_double_bracket_before_mac_placeholder() {
    // SECURITY invariant: the `[[` delimiter marks an empty MAC-input range,
    // which is what every standard Bolt Card server expects. standardize must
    // insert it immediately before `{mac}` so the card computes CMAC over an
    // empty range and the server's matching computation agrees.
    let url = "https://example.com/?p={picc:uid+ctr}&c={mac}";
    let standardized = standardize_url_template(url);
    assert!(
        standardized.contains("[[{mac}"),
        "standardize must place [[ immediately before {{mac}}, got: {standardized:?}"
    );
}

#[test]
fn standardize_preserves_picc_placeholder() {
    // SECURITY invariant: the {picc:...} placeholder must survive
    // standardization unchanged. A regression that rewrote or dropped it would
    // silently break UID/counter decryption server-side.
    let url = "https://example.com/?p={picc:uid+ctr}&c={mac}";
    let standardized = standardize_url_template(url);
    assert!(
        standardized.contains("{picc:uid+ctr}"),
        "picc placeholder must survive standardization, got: {standardized:?}"
    );
}

#[test]
fn standardize_is_idempotent() {
    // SECURITY invariant: running standardize twice must not double-insert
    // `[[` or otherwise mangle the URL. A non-idempotent transform would
    // corrupt re-burn workflows where the same URL is standardized again.
    let url = "https://example.com/?p={picc:uid+ctr}&c={mac}";
    let once = standardize_url_template(url);
    let twice = standardize_url_template(&once);
    assert_eq!(once, twice, "standardize must be idempotent");
    assert!(
        twice.matches("[[").count() == 1,
        "exactly one [[ delimiter must be present, got: {twice:?}"
    );
}

#[test]
fn standardize_leaves_already_delimited_url_untouched() {
    // SECURITY invariant: a URL already carrying `[[{mac}` is returned
    // verbatim. This guards against a "helpful" regression that strips and
    // re-inserts the delimiter (which could reorder adjacent bytes).
    let url = "https://example.com/?p={picc:uid+ctr}&c=[[{mac}";
    assert_eq!(standardize_url_template(url), url);
}

#[test]
fn standardize_without_mac_placeholder_is_a_noop_insert() {
    // SECURITY invariant: a URL lacking `{mac}` must not have `[[` injected,
    // because there is nothing to delimit. This documents the contract that
    // the *burn command* (not the library) is the gatekeeper that rejects
    // placeholder-less URLs — the library never silently fabricates them.
    let url = "https://example.com/?p={picc:uid+ctr}";
    let standardized = standardize_url_template(url);
    assert_eq!(
        standardized, url,
        "standardize must not inject [[ without a {{mac}} placeholder"
    );
}

#[test]
fn standardize_handles_multiple_mac_placeholders() {
    // SECURITY invariant: if a URL (pathologically) contains `{mac}` twice,
    // standardize replaces both. This pins the current `str::replace`
    // behaviour so a future switch to `replace_first` does not silently leave
    // the second occurrence undelimited.
    let url = "https://example.com/?c={mac}&d={mac}";
    let standardized = standardize_url_template(url);
    assert_eq!(standardized.matches("[[{mac}").count(), 2);
}
