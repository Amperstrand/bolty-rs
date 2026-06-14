use crate::crypto::aes_cmac;
use crate::secret::{AesKey, CardKeys};
use core::fmt;
use zeroize::Zeroize;

const DEFAULT_BOLTCARD_VERSION: u32 = 1;

const TAG_CARD_KEY: [u8; 4] = [0x2D, 0x00, 0x3F, 0x75];
const TAG_K0: [u8; 4] = [0x2D, 0x00, 0x3F, 0x76];
const TAG_K1: [u8; 4] = [0x2D, 0x00, 0x3F, 0x77];
const TAG_K2: [u8; 4] = [0x2D, 0x00, 0x3F, 0x78];
const TAG_K3: [u8; 4] = [0x2D, 0x00, 0x3F, 0x79];
const TAG_K4: [u8; 4] = [0x2D, 0x00, 0x3F, 0x7A];
const TAG_CARD_ID: [u8; 4] = [0x2D, 0x00, 0x3F, 0x7B];

/// Which key derivation strategy to use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DerivationStrategy {
    /// Boltcard deterministic derivation (default product behavior).
    #[default]
    BoltcardDeterministic,
    /// NXP AN10922 diversification (low-level/compatibility only).
    An10922,
}

/// Trait for computing card keys from UID + issuer key.
pub trait KeyDeriver {
    type Error;

    fn derive_keys(
        &self,
        uid: &[u8; 7],
        issuer_key: &AesKey,
        strategy: DerivationStrategy,
    ) -> Result<CardKeys, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationError {
    UnsupportedStrategy,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CardKeySet {
    pub card_key: AesKey,
    pub k0: AesKey,
    pub k1: AesKey,
    pub k2: AesKey,
    pub k3: AesKey,
    pub k4: AesKey,
    pub card_id: [u8; 16],
}

impl Default for CardKeySet {
    fn default() -> Self {
        Self {
            card_key: AesKey::zeroed(),
            k0: AesKey::zeroed(),
            k1: AesKey::zeroed(),
            k2: AesKey::zeroed(),
            k3: AesKey::zeroed(),
            k4: AesKey::zeroed(),
            card_id: [0u8; 16],
        }
    }
}

impl fmt::Debug for CardKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CardKeySet([REDACTED])")
    }
}

impl Drop for CardKeySet {
    fn drop(&mut self) {
        self.card_id.zeroize();
    }
}

pub fn aes128_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    crate::crypto::aes_cmac(key, msg)
}

pub struct BoltcardDeterministicDeriver;

impl BoltcardDeterministicDeriver {
    pub fn derive_card_key(issuer_key: &[u8; 16], uid: &[u8; 7], version: u32) -> [u8; 16] {
        let mut message = [0u8; 15];
        message[..4].copy_from_slice(&TAG_CARD_KEY);
        message[4..11].copy_from_slice(uid);
        message[11..].copy_from_slice(&version.to_le_bytes());
        aes_cmac(issuer_key, &message)
    }

    pub fn derive_keys(issuer_key: &[u8; 16], uid: &[u8; 7], version: u32) -> CardKeySet {
        let card_key = Self::derive_card_key(issuer_key, uid, version);

        CardKeySet {
            card_key: AesKey::new(card_key),
            k0: AesKey::new(aes_cmac(&card_key, &TAG_K0)),
            k1: AesKey::new(aes_cmac(issuer_key, &TAG_K1)),
            k2: AesKey::new(aes_cmac(&card_key, &TAG_K2)),
            k3: AesKey::new(aes_cmac(&card_key, &TAG_K3)),
            k4: AesKey::new(aes_cmac(&card_key, &TAG_K4)),
            card_id: Self::derive_card_id(issuer_key, uid),
        }
    }

    pub fn derive_card_id(issuer_key: &[u8; 16], uid: &[u8; 7]) -> [u8; 16] {
        let mut message = [0u8; 11];
        message[..4].copy_from_slice(&TAG_CARD_ID);
        message[4..].copy_from_slice(uid);
        aes_cmac(issuer_key, &message)
    }
}

impl KeyDeriver for BoltcardDeterministicDeriver {
    type Error = DerivationError;

    fn derive_keys(
        &self,
        uid: &[u8; 7],
        issuer_key: &AesKey,
        strategy: DerivationStrategy,
    ) -> Result<CardKeys, Self::Error> {
        let derived = match strategy {
            DerivationStrategy::BoltcardDeterministic => {
                Self::derive_keys(issuer_key.as_bytes(), uid, DEFAULT_BOLTCARD_VERSION)
            }
            DerivationStrategy::An10922 => {
                return Err(DerivationError::UnsupportedStrategy);
            }
        };

        Ok(CardKeys {
            k0: derived.k0.clone(),
            k1: derived.k1.clone(),
            k2: derived.k2.clone(),
            k3: derived.k3.clone(),
            k4: derived.k4.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AesKey, BoltcardDeterministicDeriver, CardKeySet, DerivationStrategy};

    const FIXTURES: &str =
        include_str!("../../../tests/fixtures/derivation/boltcard_deterministic.toml");

    #[derive(Clone, Default)]
    struct FixtureVector {
        description: &'static str,
        issuer_key: [u8; 16],
        uid: [u8; 7],
        version: u32,
        expected: CardKeySet,
    }

    #[test]
    fn deterministic_derivation_vectors() {
        for vector in parse_fixture_vectors() {
            let actual = BoltcardDeterministicDeriver::derive_keys(
                &vector.issuer_key,
                &vector.uid,
                vector.version,
            );

            assert_key_eq(vector.description, "card_key", &actual.card_key, &vector.expected.card_key);
            assert_key_eq(vector.description, "k0", &actual.k0, &vector.expected.k0);
            assert_key_eq(vector.description, "k1", &actual.k1, &vector.expected.k1);
            assert_key_eq(vector.description, "k2", &actual.k2, &vector.expected.k2);
            assert_key_eq(vector.description, "k3", &actual.k3, &vector.expected.k3);
            assert_key_eq(vector.description, "k4", &actual.k4, &vector.expected.k4);
            assert_eq!(actual.card_id, vector.expected.card_id, "{} card_id mismatch", vector.description);
        }
    }

    #[test]
    fn strategy_selection() {
        assert_eq!(
            DerivationStrategy::default(),
            DerivationStrategy::BoltcardDeterministic
        );
    }

    fn parse_fixture_vectors() -> [FixtureVector; 3] {
        let mut vectors = [
            FixtureVector::default(),
            FixtureVector::default(),
            FixtureVector::default(),
        ];
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
                "issuer_key" => current.issuer_key = parse_hex_array(value),
                "uid" => current.uid = parse_hex_array(value),
                "version" => current.version = value.parse().expect("invalid fixture version"),
                "card_key" => current.expected.card_key = AesKey::new(parse_hex_array(value)),
                "k0" => current.expected.k0 = AesKey::new(parse_hex_array(value)),
                "k1" => current.expected.k1 = AesKey::new(parse_hex_array(value)),
                "k2" => current.expected.k2 = AesKey::new(parse_hex_array(value)),
                "k3" => current.expected.k3 = AesKey::new(parse_hex_array(value)),
                "k4" => current.expected.k4 = AesKey::new(parse_hex_array(value)),
                "card_id" => current.expected.card_id = parse_hex_array(value),
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

    fn parse_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        crate::util::decode_hex(hex).expect("invalid hex in fixture")
    }

    fn assert_key_eq(label: &str, name: &str, actual: &AesKey, expected: &AesKey) {
        assert_eq!(actual, expected, "{label} {name} mismatch");
    }
}
