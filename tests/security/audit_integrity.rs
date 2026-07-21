//! SECURITY: Audit integrity — provenance tags have a deterministic, parseable
//! format.
//!
//! Invariant: `KeyProvenance` renders into two stable, machine-parseable
//! forms used by the audit log and the JSON diagnose output. A regression in
//! either form breaks forensic parsing and lets an attacker inject or spoof
//! provenance tags. The contract is owned by `bolty-core`; the actual log
//! *writing* (tag placement at end-of-line) is verified inline in
//! `bolty-cli/src/audit.rs`.

use bolty_core::provenance::KeyProvenance;

#[test]
fn factory_default_audit_tag_is_stable_literal() {
    // SECURITY invariant: the factory-default tag must be the exact literal
    // `FactoryDefault`. Audit-log parsers (grep, jq, SIEM) match on it; a
    // rename would silently break alerting on blank-card burns.
    assert_eq!(
        KeyProvenance::FactoryDefault.to_audit_tag(),
        "FactoryDefault"
    );
}

#[test]
fn derived_issuer_audit_tag_includes_version() {
    // SECURITY invariant: DerivedIssuer must embed the key version so an
    // auditor can distinguish a v1 burn from a v2 burn in the log. The format
    // is `DerivedIssuer(<version>)`.
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 1 }.to_audit_tag(),
        "DerivedIssuer(1)"
    );
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 200 }.to_audit_tag(),
        "DerivedIssuer(200)"
    );
}

#[test]
fn static_test_key_audit_tag_is_stable_literal() {
    // SECURITY invariant: the M5StickC static-test-key tag is a distinct,
    // recognisable literal so auditors can flag cards burned with known
    // insecure test keys.
    assert_eq!(KeyProvenance::StaticTestKey.to_audit_tag(), "StaticTestKey");
}

#[test]
fn unknown_external_audit_tag_signals_untrusted() {
    // SECURITY invariant: an unrecognised card must tag as `UnknownExternal`,
    // never as one of the trusted variants. This is the fail-closed label.
    assert_eq!(
        KeyProvenance::UnknownExternal.to_audit_tag(),
        "UnknownExternal"
    );
}

#[test]
fn json_name_collapses_derived_versions() {
    // SECURITY invariant: the flat JSON name drops the version (the version
    // travels in a sibling field). This keeps `key_provenance` a stable enum
    // key in the JSON schema even as new versions ship.
    assert_eq!(
        KeyProvenance::FactoryDefault.as_json_name(),
        "FactoryDefault"
    );
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 1 }.as_json_name(),
        "DerivedIssuer"
    );
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 99 }.as_json_name(),
        "DerivedIssuer"
    );
    assert_eq!(KeyProvenance::StaticTestKey.as_json_name(), "StaticTestKey");
    assert_eq!(
        KeyProvenance::UnknownExternal.as_json_name(),
        "UnknownExternal"
    );
}

#[test]
fn json_version_only_for_derived_issuer() {
    // SECURITY invariant: only DerivedIssuer carries a version in JSON. The
    // other variants must return None so the JSON builder omits the field
    // entirely (a spurious `key_provenance_version: null` would break
    // schema-strict consumers).
    assert_eq!(KeyProvenance::FactoryDefault.json_version(), None);
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 7 }.json_version(),
        Some(7)
    );
    assert_eq!(KeyProvenance::StaticTestKey.json_version(), None);
    assert_eq!(KeyProvenance::UnknownExternal.json_version(), None);
}

#[test]
fn audit_tags_contain_no_whitespace_or_injection_chars() {
    // SECURITY invariant: tags must not contain spaces, brackets, or quote
    // characters that could let a malformed value break the audit-line or
    // JSON structure. Every tag is a bare identifier (plus parens+digits for
    // the versioned form).
    for prov in [
        KeyProvenance::FactoryDefault,
        KeyProvenance::DerivedIssuer { version: 1 },
        KeyProvenance::DerivedIssuer { version: 255 },
        KeyProvenance::StaticTestKey,
        KeyProvenance::UnknownExternal,
    ] {
        let tag = prov.to_audit_tag();
        assert!(
            tag.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '(' || c == ')'),
            "audit tag contains unexpected chars: {tag:?}"
        );
        assert!(
            !tag.contains(' '),
            "audit tag must not contain spaces (would break space-delimited parsing): {tag:?}"
        );
    }
}
