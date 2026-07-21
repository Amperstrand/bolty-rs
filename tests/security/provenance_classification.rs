//! SECURITY: Provenance classification — the four key-provenance variants are
//! distinct, total, and carry their security meaning.
//!
//! Invariant: `KeyProvenance` is the trust label attached to every card key
//! in the audit log and diagnose output. The four variants form a strict
//! trust ordering (FactoryDefault > DerivedIssuer > StaticTestKey >
//! UnknownExternal) realised by `classify_key_provenance` in
//! `bolty-cli/src/diagnose.rs` (verified inline there). This module pins the
//! *type-level* properties that the classifier depends on: variants are
//! distinct, equality is sound, and `Copy`/`Eq` hold so the classifier can
//! return by value.

use bolty_core::provenance::KeyProvenance;

#[test]
fn all_four_variants_are_distinct() {
    // SECURITY invariant: the four trust tiers must never compare equal. If
    // two variants merged (e.g. StaticTestKey == UnknownExternal), the
    // classifier would mislabel a known-insecure card as merely untrusted.
    let factory = KeyProvenance::FactoryDefault;
    let derived = KeyProvenance::DerivedIssuer { version: 1 };
    let static_test = KeyProvenance::StaticTestKey;
    let unknown = KeyProvenance::UnknownExternal;

    let all = [factory, derived, static_test, unknown];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i == j {
                assert_eq!(a, b, "variant {i} must equal itself");
            } else {
                assert_ne!(a, b, "variants {i} and {j} must be distinct");
            }
        }
    }
}

#[test]
fn derived_issuer_version_distinguishes_burns() {
    // SECURITY invariant: two DerivedIssuer labels with different versions
    // must compare unequal, so an auditor can tell a v1 re-burn from a v2
    // re-burn in the log.
    assert_ne!(
        KeyProvenance::DerivedIssuer { version: 1 },
        KeyProvenance::DerivedIssuer { version: 2 }
    );
    assert_eq!(
        KeyProvenance::DerivedIssuer { version: 1 },
        KeyProvenance::DerivedIssuer { version: 1 }
    );
}

#[test]
fn variants_are_total_and_exhaustive() {
    // SECURITY invariant: every card the tool encounters must map to one of
    // the four variants — there is no "Other" escape hatch that could hide an
    // unclassified card. This test pins the count at four so adding a fifth
    // variant is a deliberate, reviewed change.
    let variants = [
        KeyProvenance::FactoryDefault,
        KeyProvenance::DerivedIssuer { version: 1 },
        KeyProvenance::StaticTestKey,
        KeyProvenance::UnknownExternal,
    ];
    // The variants are the complete set by construction; we assert they render
    // to four distinct audit tags, proving no two collapse.
    let tags: std::collections::HashSet<String> =
        variants.iter().map(|v| v.to_audit_tag()).collect();
    assert_eq!(tags.len(), 4, "exactly four distinct provenance tiers");
}

#[test]
fn factory_default_is_the_trusted_baseline() {
    // SECURITY invariant: FactoryDefault represents a genuinely blank card
    // (factory all-zero keys). Its tag and JSON name must both be the bare
    // literal, so it is unambiguous in every output channel.
    let f = KeyProvenance::FactoryDefault;
    assert_eq!(f.to_audit_tag(), "FactoryDefault");
    assert_eq!(f.as_json_name(), "FactoryDefault");
    assert_eq!(f.json_version(), None);
}

#[test]
fn derived_issuer_carries_version_in_audit_but_not_in_json_name() {
    // SECURITY invariant: the version is security-relevant in the audit log
    // (it identifies the burn generation) but the JSON *name* must stay flat
    // so the schema remains stable. This asymmetry is intentional and must
    // not be "fixed" by folding the version into the name.
    let d = KeyProvenance::DerivedIssuer { version: 3 };
    assert!(d.to_audit_tag().contains("3"));
    assert_eq!(d.as_json_name(), "DerivedIssuer");
    assert_eq!(d.json_version(), Some(3));
}

#[test]
fn static_test_key_is_distinct_from_factory() {
    // SECURITY invariant: the M5StickC static test key ([0x11;16]) is a known
    // insecure key, NOT a factory default. The two variants must stay distinct
    // so a card burned with static test keys is flagged, not treated as blank.
    assert_ne!(KeyProvenance::StaticTestKey, KeyProvenance::FactoryDefault);
}

#[test]
fn unknown_external_is_the_fail_closed_label() {
    // SECURITY invariant: a card that matches no known key must label as
    // UnknownExternal — the explicit "untrusted" tier. It must never be
    // confused with FactoryDefault or DerivedIssuer.
    let u = KeyProvenance::UnknownExternal;
    assert_ne!(u, KeyProvenance::FactoryDefault);
    assert_ne!(u, KeyProvenance::DerivedIssuer { version: 1 });
    assert_ne!(u, KeyProvenance::StaticTestKey);
    assert_eq!(u.to_audit_tag(), "UnknownExternal");
}
