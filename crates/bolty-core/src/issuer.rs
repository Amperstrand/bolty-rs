use crate::{
    assessment::{CardAssessment, CardState, IdleCardKind, KeyConfidence},
    config::IssuerConfig,
    constants::{KEY_VERSION_BLANK, NUM_KEYS, UID_LEN},
    derivation::{BoltcardDeterministicDeriver, CardKeySet},
};

#[derive(Debug, Clone, Copy)]
pub struct IssuerRegistry<'a> {
    issuers: &'a [IssuerConfig],
}

impl<'a> IssuerRegistry<'a> {
    pub const fn new(issuers: &'a [IssuerConfig]) -> Self {
        Self { issuers }
    }

    pub const fn issuers(&self) -> &'a [IssuerConfig] {
        self.issuers
    }

    pub fn match_issuer(&self, uid: &[u8; UID_LEN], key_version: u8) -> Option<(usize, CardKeySet)> {
        match_issuer(uid, key_version, self.issuers)
    }

    pub fn assess_card(&self, uid: &[u8; UID_LEN], key_versions: [u8; NUM_KEYS]) -> CardAssessment {
        assess_card(uid, key_versions, self.issuers)
    }
}

pub fn match_issuer(
    uid: &[u8; UID_LEN],
    key_version: u8,
    issuers: &[IssuerConfig],
) -> Option<(usize, CardKeySet)> {
    issuers.iter().enumerate().find_map(|(idx, issuer)| {
        let derived = BoltcardDeterministicDeriver::derive_keys(
            issuer.issuer_key.as_bytes(),
            uid,
            issuer.derivation_version,
        );

        if issuer.key_version == key_version {
            Some((idx, derived))
        } else {
            None
        }
    })
}

pub fn assess_card(
    uid: &[u8; UID_LEN],
    key_versions: [u8; NUM_KEYS],
    issuers: &[IssuerConfig],
) -> CardAssessment {
    let mut assessment = base_assessment(uid, key_versions);

    if key_versions.iter().all(|version| *version == KEY_VERSION_BLANK) {
        assessment.state = CardState::Blank;
        assessment.kind = IdleCardKind::Blank;
        assessment.zero_key_auth_ok = true;
        assessment.reset_eligible = true;
        return assessment;
    }

    if let Some((issuer_idx, _derived_keys)) = match_issuer(uid, key_versions[1], issuers) {
        assessment.state = CardState::Provisioned(issuer_idx);
        assessment.kind = IdleCardKind::Provisioned;
        assessment.key_confidence = [KeyConfidence::Full; NUM_KEYS];
        assessment.looks_like_boltcard = true;
        assessment.deterministic_k1_match = true;
        assessment.deterministic_full_match = true;
        assessment.reset_eligible = true;
        return assessment;
    }

    assessment.state = CardState::Foreign;
    assessment.kind = IdleCardKind::Unknown;
    assessment.looks_like_boltcard = true;
    assessment
}

fn base_assessment(uid: &[u8; UID_LEN], key_versions: [u8; NUM_KEYS]) -> CardAssessment {
    let mut uid_storage = [0u8; 12];
    uid_storage[..UID_LEN].copy_from_slice(uid);

    CardAssessment {
        present: true,
        uid: Some(uid_storage),
        uid_len: UID_LEN as u8,
        key_versions,
        ..CardAssessment::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::IssuerConfig, secret::AesKey};

    const FIXTURES: &str =
        include_str!("../../../tests/fixtures/assessment/issuer_matching.toml");

    #[derive(Clone, Copy, Default)]
    struct FixtureVector {
        description: &'static str,
        uid: [u8; UID_LEN],
        key_versions: [u8; NUM_KEYS],
        expected_state: &'static str,
        expected_issuer: Option<usize>,
    }

    #[test]
    fn assesses_fixture_vectors() {
        let issuers = issuer_fixtures();

        for vector in parse_fixture_vectors() {
            let assessment = assess_card(&vector.uid, vector.key_versions, &issuers);

            match (vector.expected_state, assessment.state) {
                ("Blank", CardState::Blank) => {}
                ("Provisioned", CardState::Provisioned(idx)) => {
                    assert_eq!(Some(idx), vector.expected_issuer, "{} issuer mismatch", vector.description);
                }
                ("Foreign", CardState::Foreign) => {}
                _ => panic!("unexpected assessment state for {}", vector.description),
            }
        }
    }

    #[test]
    fn issuer_match_returns_derived_keys_for_known_issuer() {
        let issuers = issuer_fixtures();
        let vector = parse_fixture_vectors()[1];

        let matched = match_issuer(&vector.uid, vector.key_versions[1], &issuers)
            .expect("known issuer should match");

        assert_eq!(matched.0, 1);
        assert_eq!(matched.1.k1, BoltcardDeterministicDeriver::derive_keys(
            issuers[1].issuer_key.as_bytes(),
            &vector.uid,
            issuers[1].derivation_version,
        ).k1);
    }

    fn issuer_fixtures() -> [IssuerConfig; 2] {
        [
            IssuerConfig {
                issuer_key: AesKey::new([0x11; 16]),
                key_version: 0x21,
                ..IssuerConfig::default()
            },
            IssuerConfig {
                issuer_key: AesKey::new([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]),
                key_version: 0x42,
                ..IssuerConfig::default()
            },
        ]
    }

    fn parse_fixture_vectors() -> [FixtureVector; 3] {
        let mut vectors = [FixtureVector::default(); 3];
        let mut current = FixtureVector::default();
        let mut vector_count = 0usize;
        let mut in_vector = false;

        for raw_line in FIXTURES.lines() {
            let line = raw_line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line == "[[vectors]]" {
                if in_vector {
                    vectors[vector_count] = current;
                    vector_count += 1;
                    current = FixtureVector::default();
                }
                in_vector = true;
                continue;
            }

            if !in_vector || line.starts_with('[') {
                continue;
            }

            let (key, raw_value) = line
                .split_once('=')
                .expect("fixture entries must contain '='");
            let value = raw_value.trim().trim_matches('"');

            match key.trim() {
                "description" => current.description = value,
                "uid" => current.uid = parse_hex_array(value),
                "key_versions" => current.key_versions = parse_u8_list(value),
                "expected_state" => current.expected_state = value,
                "expected_issuer" => {
                    current.expected_issuer = if value == "none" {
                        None
                    } else {
                        Some(value.parse().expect("invalid issuer index"))
                    }
                }
                _ => {}
            }
        }

        if in_vector {
            vectors[vector_count] = current;
            vector_count += 1;
        }

        assert_eq!(vector_count, vectors.len(), "unexpected fixture vector count");
        vectors
    }

    fn parse_u8_list(input: &str) -> [u8; NUM_KEYS] {
        let values = input
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .expect("array fixture must be bracketed");
        let mut parsed = [0u8; NUM_KEYS];

        for (idx, item) in values.split(',').enumerate() {
            parsed[idx] = parse_u8(item.trim());
        }

        parsed
    }

    fn parse_u8(input: &str) -> u8 {
        if let Some(hex) = input.strip_prefix("0x") {
            u8::from_str_radix(hex, 16).expect("invalid hex value")
        } else {
            input.parse().expect("invalid integer value")
        }
    }

    fn parse_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2, "hex string length mismatch");

        let mut bytes = [0u8; N];
        let raw = hex.as_bytes();

        for (index, chunk) in raw.chunks_exact(2).enumerate() {
            bytes[index] = (decode_hex_nibble(chunk[0]) << 4) | decode_hex_nibble(chunk[1]);
        }

        bytes
    }

    fn decode_hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex nibble: {byte}"),
        }
    }
}
