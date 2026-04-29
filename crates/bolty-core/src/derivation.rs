use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::secret::{AesKey, CardKeys};

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CardKeySet {
    pub card_key: [u8; 16],
    pub k0: [u8; 16],
    pub k1: [u8; 16],
    pub k2: [u8; 16],
    pub k3: [u8; 16],
    pub k4: [u8; 16],
    pub card_id: [u8; 16],
}

pub fn aes128_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .expect("AES-128-CMAC requires a 16-byte key");
    mac.update(msg);

    let mut output = [0u8; 16];
    output.copy_from_slice(&mac.finalize().into_bytes());
    output
}

pub struct BoltcardDeterministicDeriver;

impl BoltcardDeterministicDeriver {
    pub fn derive_card_key(issuer_key: &[u8; 16], uid: &[u8; 7], version: u32) -> [u8; 16] {
        let mut message = [0u8; 15];
        message[..4].copy_from_slice(&TAG_CARD_KEY);
        message[4..11].copy_from_slice(uid);
        message[11..].copy_from_slice(&version.to_le_bytes());
        aes128_cmac(issuer_key, &message)
    }

    pub fn derive_keys(issuer_key: &[u8; 16], uid: &[u8; 7], version: u32) -> CardKeySet {
        let card_key = Self::derive_card_key(issuer_key, uid, version);

        CardKeySet {
            card_key,
            k0: aes128_cmac(&card_key, &TAG_K0),
            k1: aes128_cmac(issuer_key, &TAG_K1),
            k2: aes128_cmac(&card_key, &TAG_K2),
            k3: aes128_cmac(&card_key, &TAG_K3),
            k4: aes128_cmac(&card_key, &TAG_K4),
            card_id: Self::derive_card_id(issuer_key, uid),
        }
    }

    pub fn derive_card_id(issuer_key: &[u8; 16], uid: &[u8; 7]) -> [u8; 16] {
        let mut message = [0u8; 11];
        message[..4].copy_from_slice(&TAG_CARD_ID);
        message[4..].copy_from_slice(uid);
        aes128_cmac(issuer_key, &message)
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
            DerivationStrategy::An10922 => todo!("AN10922 derivation is not implemented yet"),
        };

        Ok(CardKeys {
            k0: AesKey::new(derived.k0),
            k1: AesKey::new(derived.k1),
            k2: AesKey::new(derived.k2),
            k3: AesKey::new(derived.k3),
            k4: AesKey::new(derived.k4),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BoltcardDeterministicDeriver, CardKeySet, DerivationStrategy};

    const FIXTURES: &str =
        include_str!("../../../tests/fixtures/derivation/boltcard_deterministic.toml");

    #[derive(Clone, Copy, Default)]
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

            assert_key_eq(
                vector.description,
                "card_key",
                actual.card_key,
                vector.expected.card_key,
            );
            assert_key_eq(vector.description, "k0", actual.k0, vector.expected.k0);
            assert_key_eq(vector.description, "k1", actual.k1, vector.expected.k1);
            assert_key_eq(vector.description, "k2", actual.k2, vector.expected.k2);
            assert_key_eq(vector.description, "k3", actual.k3, vector.expected.k3);
            assert_key_eq(vector.description, "k4", actual.k4, vector.expected.k4);
            assert_key_eq(
                vector.description,
                "card_id",
                actual.card_id,
                vector.expected.card_id,
            );
        }
    }

    #[test]
    fn strategy_selection() {
        assert_eq!(
            DerivationStrategy::default(),
            DerivationStrategy::BoltcardDeterministic
        );
    }

    fn parse_fixture_vectors() -> [FixtureVector; 2] {
        let mut vectors = [FixtureVector::default(); 2];
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
                "card_key" => current.expected.card_key = parse_hex_array(value),
                "k0" => current.expected.k0 = parse_hex_array(value),
                "k1" => current.expected.k1 = parse_hex_array(value),
                "k2" => current.expected.k2 = parse_hex_array(value),
                "k3" => current.expected.k3 = parse_hex_array(value),
                "k4" => current.expected.k4 = parse_hex_array(value),
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

    fn assert_key_eq(label: &str, name: &str, actual: [u8; 16], expected: [u8; 16]) {
        assert_eq!(actual, expected, "{label} {name} mismatch");
    }
}
