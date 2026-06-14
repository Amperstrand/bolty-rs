#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bolty_core::{
    assessment::CardState,
    config::IssuerConfig,
    derivation::BoltcardDeterministicDeriver,
    issuer::assess_card,
    picc::{extract_p_and_c, picc_parse_url},
    secret::AesKey,
    uid::CardUid,
};

const UID_BLANK: [u8; 7] = [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80];
const UID_PROVISIONED: [u8; 7] = [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80];
const UID_FOREIGN: [u8; 7] = [0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];
const ISSUER_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const PICC_URL: &str =
    "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298";
const PICC_P: &str = "E61CB056F52D34F9368F079D1814D2CF";
const PICC_C: &str = "FCC9A22201EA2298";
const PICC_K1: [u8; 16] = [
    0x55, 0xDA, 0x17, 0x4C, 0x96, 0x08, 0x99, 0x3D, 0xC2, 0x7B, 0xB3, 0xF3, 0x0A, 0x4A, 0x73, 0x14,
];
const PICC_K2: [u8; 16] = [
    0x2A, 0xB7, 0x4A, 0xBC, 0x12, 0x73, 0xFB, 0x43, 0xCA, 0xE9, 0x75, 0x53, 0xA3, 0x6D, 0x4D, 0x08,
];

#[test]
fn blank_card_assessment_returns_blank() {
    let assessment = assess_card(CardUid::new(UID_BLANK), [0u8; 5], &[]);

    assert_eq!(assessment.state, CardState::Blank);
}

#[test]
fn provisioned_card_assessment_returns_provisioned() {
    let issuer = IssuerConfig {
        issuer_key: AesKey::new(ISSUER_KEY),
        derivation_version: 1,
        key_version: 0x42,
        ..IssuerConfig::default()
    };
    let derived = BoltcardDeterministicDeriver::derive_keys(
        issuer.issuer_key.as_bytes(),
        CardUid::new(UID_PROVISIONED),
        issuer.derivation_version,
    );
    let expected_key_version = issuer.key_version;
    let assessment = assess_card(
        CardUid::new(UID_PROVISIONED),
        [expected_key_version; 5],
        &[issuer],
    );

    assert_eq!(derived.k1.as_bytes(), &PICC_K1);
    assert_eq!(assessment.state, CardState::Provisioned(0));
}

#[test]
fn foreign_card_assessment_returns_foreign() {
    let issuer = IssuerConfig {
        issuer_key: AesKey::new(ISSUER_KEY),
        derivation_version: 1,
        key_version: 0x42,
        ..IssuerConfig::default()
    };
    let assessment = assess_card(CardUid::new(UID_FOREIGN), [0x99; 5], &[issuer]);

    assert_eq!(assessment.state, CardState::Foreign);
}

#[test]
fn picc_parse_url_extracts_fixture_bytes() {
    let (p_hex, c_hex) = extract_p_and_c(PICC_URL).expect("fixture URL should contain p and c");
    let picc = picc_parse_url(&PICC_K1, &PICC_K2, PICC_URL);

    assert_eq!(p_hex, PICC_P);
    assert_eq!(c_hex, PICC_C);
    assert!(picc.valid);
    assert_eq!(picc.uid, UID_PROVISIONED);
    assert_eq!(picc.counter, 0);
}

// ── Derivation consistency ─────────────────────────────────────────

#[test]
fn derivation_is_deterministic_same_inputs_yield_same_keys() {
    let keys_a =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let keys_b =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);

    assert_eq!(keys_a.card_key, keys_b.card_key);
    assert_eq!(keys_a.k0, keys_b.k0);
    assert_eq!(keys_a.k1, keys_b.k1);
    assert_eq!(keys_a.k2, keys_b.k2);
    assert_eq!(keys_a.k3, keys_b.k3);
    assert_eq!(keys_a.k4, keys_b.k4);
    assert_eq!(keys_a.card_id, keys_b.card_id);
}

#[test]
fn derivation_differs_across_different_uids() {
    let keys_a =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let keys_b =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_FOREIGN), 1);

    assert_ne!(keys_a.card_key, keys_b.card_key);
    assert_ne!(keys_a.k0, keys_b.k0);
    assert_ne!(keys_a.k2, keys_b.k2);
    assert_ne!(keys_a.card_id, keys_b.card_id);
}

#[test]
fn derivation_k1_is_issuer_keyed_not_uid_keyed() {
    let keys_a =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let keys_b =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_FOREIGN), 1);

    assert_eq!(
        keys_a.k1, keys_b.k1,
        "K1 is derived from issuer_key only, must be same for same issuer"
    );
}

#[test]
fn derivation_differs_across_versions() {
    let keys_v1 =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let keys_v2 =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 2);

    assert_ne!(keys_v1.card_key, keys_v2.card_key);
    assert_ne!(keys_v1.k0, keys_v2.k0);
    assert_ne!(keys_v1.k2, keys_v2.k2);
}

#[test]
fn derivation_differs_across_issuer_keys() {
    let other_key: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let keys_a =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let keys_b =
        BoltcardDeterministicDeriver::derive_keys(&other_key, CardUid::new(UID_PROVISIONED), 1);

    assert_ne!(keys_a.card_key, keys_b.card_key);
    assert_ne!(keys_a.k1, keys_b.k1);
    assert_ne!(keys_a.card_id, keys_b.card_id);
}

#[test]
fn derived_k1_matches_fixture_vector() {
    let keys =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);

    assert_eq!(keys.k1.as_bytes(), &PICC_K1);
    assert_eq!(keys.k2.as_bytes(), &PICC_K2);
}

// ── Issuer registry matching ───────────────────────────────────────

#[test]
fn multiple_issuers_match_first_compatible() {
    let issuer_a = IssuerConfig {
        issuer_key: AesKey::new([0x11; 16]),
        derivation_version: 1,
        key_version: 0x21,
        ..IssuerConfig::default()
    };
    let issuer_b = IssuerConfig {
        issuer_key: AesKey::new(ISSUER_KEY),
        derivation_version: 1,
        key_version: 0x42,
        ..IssuerConfig::default()
    };
    let issuers = [issuer_a, issuer_b];

    let assessment = assess_card(CardUid::new(UID_PROVISIONED), [0x42; 5], &issuers);

    assert_eq!(assessment.state, CardState::Provisioned(1));
}

#[test]
fn no_issuers_yields_foreign_for_provisioned_key_versions() {
    let assessment = assess_card(CardUid::new(UID_PROVISIONED), [0x42; 5], &[]);

    assert_eq!(assessment.state, CardState::Foreign);
}

#[test]
fn issuer_wrong_version_yields_foreign() {
    let issuer = IssuerConfig {
        issuer_key: AesKey::new(ISSUER_KEY),
        derivation_version: 1,
        key_version: 0x99,
        ..IssuerConfig::default()
    };
    let assessment = assess_card(CardUid::new(UID_PROVISIONED), [0x42; 5], &[issuer]);

    assert_eq!(assessment.state, CardState::Foreign);
}

#[test]
fn blank_overrides_issuer_match_when_all_zero_versions() {
    let issuer = IssuerConfig {
        issuer_key: AesKey::new(ISSUER_KEY),
        derivation_version: 1,
        key_version: 0x00,
        ..IssuerConfig::default()
    };
    let assessment = assess_card(CardUid::new(UID_BLANK), [0x00; 5], &[issuer]);

    assert_eq!(assessment.state, CardState::Blank);
}

// ── CardUid operations ─────────────────────────────────────────────

#[test]
fn carduid_from_hex_roundtrip() {
    let uid = CardUid::new(UID_PROVISIONED);
    let hex = format!("{uid}");
    let parsed = CardUid::from_hex(&hex).unwrap();
    assert_eq!(uid, parsed);
}

#[test]
fn carduid_from_hex_rejects_wrong_length() {
    assert!(CardUid::from_hex("042560").is_err());
    assert!(CardUid::from_hex("0425607A8F69801234").is_err());
}

#[test]
fn carduid_from_hex_rejects_invalid_chars() {
    assert!(CardUid::from_hex("ZZ2560507A8F6980").is_err());
}

#[test]
fn carduid_display_is_lowercase_hex() {
    let uid = CardUid::new(UID_PROVISIONED);
    assert_eq!(format!("{uid}"), "0425607a8f6980");
}

// ── PICC URL edge cases ────────────────────────────────────────────

#[test]
fn picc_url_with_wrong_k1_returns_invalid() {
    let wrong_k1: [u8; 16] = [0xFF; 16];
    let picc = picc_parse_url(&wrong_k1, &PICC_K2, PICC_URL);
    assert!(!picc.valid);
}

#[test]
fn picc_url_with_wrong_k2_returns_invalid() {
    let wrong_k2: [u8; 16] = [0xFF; 16];
    let picc = picc_parse_url(&PICC_K1, &wrong_k2, PICC_URL);
    assert!(!picc.valid);
}

#[test]
fn picc_url_missing_p_param_returns_invalid() {
    let url = "https://example.com/bolt?c=FCC9A22201EA2298";
    let picc = picc_parse_url(&PICC_K1, &PICC_K2, url);
    assert!(!picc.valid);
}

#[test]
fn picc_url_missing_c_param_returns_invalid() {
    let url = "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF";
    let picc = picc_parse_url(&PICC_K1, &PICC_K2, url);
    assert!(!picc.valid);
}

#[test]
fn extract_p_and_c_with_extra_query_params() {
    let url = "https://example.com/bolt?foo=bar&p=E61CB056F52D34F9368F079D1814D2CF&baz=qux&c=FCC9A22201EA2298";
    let (p, c) = extract_p_and_c(url).unwrap();
    assert_eq!(p, "E61CB056F52D34F9368F079D1814D2CF");
    assert_eq!(c, "FCC9A22201EA2298");
}

#[test]
fn extract_p_and_c_empty_url_returns_none() {
    assert!(extract_p_and_c("").is_none());
}

// ── CardKeySet security properties ─────────────────────────────────

#[test]
fn card_key_set_debug_does_not_leak_key_material() {
    let keys =
        BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID_PROVISIONED), 1);
    let debug_str = format!("{keys:?}");
    assert_eq!(debug_str, "CardKeySet([REDACTED])");
}
