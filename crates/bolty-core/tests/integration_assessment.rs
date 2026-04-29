use bolty_core::{
    assessment::CardState,
    config::IssuerConfig,
    derivation::BoltcardDeterministicDeriver,
    issuer::assess_card,
    picc::{extract_p_and_c, picc_parse_url},
    secret::AesKey,
};

const UID_BLANK: [u8; 7] = [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80];
const UID_PROVISIONED: [u8; 7] = [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80];
const UID_FOREIGN: [u8; 7] = [0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];
const ISSUER_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const PICC_URL: &str =
    "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298";
const PICC_P: &str = "E61CB056F52D34F9368F079D1814D2CF";
const PICC_C: &str = "FCC9A22201EA2298";
const PICC_K1: [u8; 16] = [
    0x55, 0xDA, 0x17, 0x4C, 0x96, 0x08, 0x99, 0x3D, 0xC2, 0x7B, 0xB3, 0xF3, 0x0A, 0x4A,
    0x73, 0x14,
];
const PICC_K2: [u8; 16] = [
    0x2A, 0xB7, 0x4A, 0xBC, 0x12, 0x73, 0xFB, 0x43, 0xCA, 0xE9, 0x75, 0x53, 0xA3, 0x6D,
    0x4D, 0x08,
];

#[test]
fn blank_card_assessment_returns_blank() {
    let assessment = assess_card(&UID_BLANK, [0u8; 5], &[]);

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
        &UID_PROVISIONED,
        issuer.derivation_version,
    );
    let expected_key_version = issuer.key_version;
    let assessment = assess_card(
        &UID_PROVISIONED,
        [expected_key_version; 5],
        &[issuer],
    );

    assert_eq!(derived.k1, PICC_K1);
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
    let assessment = assess_card(&UID_FOREIGN, [0x99; 5], &[issuer]);

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
