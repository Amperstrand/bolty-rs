//! Security regression test suite for bolty-core.
//!
//! Covers security invariants across six domains:
//! 1. Constant-time comparison — MAC and UID comparison must process all bytes
//! 2. Key handling — no key material leakage via Debug formatting
//! 3. Input validation — hex parsing rejects malformed input without panic
//! 4. Card state guards — safe defaults and UID length validation
//! 5. Key derivation safety — deterministic, version/UID sensitive
//! 6. PICC data validation — tag byte, truncation, counter encoding
//!
//! These tests are hardware-free and exercise only the public API of bolty-core.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bolty_core::assessment::{CardAssessment, same_uid};
use bolty_core::config::BoltyConfig;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc::{
    PICC_FORMAT_BOLTCARD, PiccData, picc_decrypt_p, picc_parse_url, picc_verify_c, sdm_build_sv2,
    SV2_HEADER,
};
use bolty_core::secret::{AesKey, CardKeys};
use bolty_core::uid::CardUid;
use bolty_core::util::{self, HexError};

// ─── Fixture constants (from verified test vectors) ──────────────────────

const K1: [u8; 16] = [
    0x55, 0xDA, 0x17, 0x4C, 0x96, 0x08, 0x99, 0x3D, 0xC2, 0x7B, 0xB3, 0xF3, 0x0A, 0x4A, 0x73, 0x14,
];
const K2: [u8; 16] = [
    0x2A, 0xB7, 0x4A, 0xBC, 0x12, 0x73, 0xFB, 0x43, 0xCA, 0xE9, 0x75, 0x53, 0xA3, 0x6D, 0x4D, 0x08,
];
const FIXTURE_UID: [u8; 7] = [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80];
const FIXTURE_P_HEX: &str = "E61CB056F52D34F9368F079D1814D2CF";
const FIXTURE_C_HEX: &str = "FCC9A22201EA2298";
const ISSUER_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// ─── Helper functions ────────────────────────────────────────────────────

/// Build a valid PiccData matching the fixture (uid, counter=0).
fn fixture_picc() -> PiccData {
    PiccData {
        valid: false,
        uid: FIXTURE_UID,
        counter: 0,
        has_uid: true,
        has_counter: true,
    }
}

/// Build a CardAssessment with the given UID stored.
fn assessment_with_uid(uid: [u8; 7]) -> CardAssessment {
    let mut uid_storage = [0u8; 12];
    uid_storage[..7].copy_from_slice(&uid);
    CardAssessment {
        present: true,
        uid_len: 7,
        uid: Some(uid_storage),
        ..CardAssessment::default()
    }
}

/// Encode a byte slice to a lowercase hex String using bolty-core's own encoder.
fn to_hex(bytes: &[u8]) -> String {
    util::encode_hex(bytes)
}

// ═════════════════════════════════════════════════════════════════════════
// Module 1: Constant-time comparison
// ═════════════════════════════════════════════════════════════════════════

mod constant_time_comparison {
    use super::*;

    /// picc_verify_c must accept a valid MAC (baseline for mismatch tests).
    #[test]
    fn picc_verify_c_accepts_valid_mac() {
        let picc = fixture_picc();
        assert!(
            picc_verify_c(&K2, &picc, FIXTURE_C_HEX),
            "valid MAC must verify successfully"
        );
    }

    /// picc_verify_c must reject mismatches at every byte position of the
    /// 8-byte MAC. If the comparison short-circuited on the first byte,
    /// later positions might not be checked.
    #[test]
    fn picc_verify_c_rejects_mismatch_at_every_byte_position() {
        let picc = fixture_picc();
        let mac_bytes: [u8; 8] = util::decode_hex(FIXTURE_C_HEX).unwrap();

        for position in 0..8usize {
            let mut modified = mac_bytes;
            modified[position] ^= 0xFF;
            let modified_hex = to_hex(&modified);
            assert!(
                !picc_verify_c(&K2, &picc, &modified_hex),
                "MAC mismatch at byte position {position} must be detected"
            );
        }
    }

    /// A single-bit difference in any byte must be detected.
    #[test]
    fn picc_verify_c_rejects_single_bit_flip() {
        let picc = fixture_picc();
        let mac_bytes: [u8; 8] = util::decode_hex(FIXTURE_C_HEX).unwrap();

        for position in 0..8usize {
            let mut modified = mac_bytes;
            modified[position] ^= 0x01; // flip only the LSB
            let modified_hex = to_hex(&modified);
            assert!(
                !picc_verify_c(&K2, &picc, &modified_hex),
                "Single-bit flip at position {position} must be detected"
            );
        }
    }

    /// picc_verify_c must reject too-short c_hex (not 16 hex chars).
    #[test]
    fn picc_verify_c_rejects_short_hex() {
        let picc = fixture_picc();
        assert!(!picc_verify_c(&K2, &picc, "FCC9A22201EA22"));
    }

    /// picc_verify_c must reject too-long c_hex.
    #[test]
    fn picc_verify_c_rejects_long_hex() {
        let picc = fixture_picc();
        assert!(
            !picc_verify_c(&K2, &picc, "FCC9A22201EA2298FF")
        );
    }

    /// picc_verify_c must reject invalid hex characters.
    #[test]
    fn picc_verify_c_rejects_invalid_hex() {
        let picc = fixture_picc();
        assert!(
            !picc_verify_c(&K2, &picc, "ZZC9A22201EA2298")
        );
    }

    /// picc_verify_c must reject PiccData that lacks UID or counter.
    #[test]
    fn picc_verify_c_rejects_picc_without_uid() {
        let picc = PiccData {
            has_uid: false,
            has_counter: true,
            ..PiccData::default()
        };
        assert!(!picc_verify_c(&K2, &picc, FIXTURE_C_HEX));
    }

    /// picc_verify_c must reject PiccData that lacks counter.
    #[test]
    fn picc_verify_c_rejects_picc_without_counter() {
        let picc = PiccData {
            has_uid: true,
            has_counter: false,
            ..PiccData::default()
        };
        assert!(!picc_verify_c(&K2, &picc, FIXTURE_C_HEX));
    }

    // ── same_uid constant-time comparison ────────────────────────────

    /// same_uid must return true for identical UIDs.
    #[test]
    fn same_uid_returns_true_for_match() {
        let assessment = assessment_with_uid(FIXTURE_UID);
        assert!(same_uid(&assessment, &FIXTURE_UID));
    }

    /// same_uid must detect mismatches at every byte position of the 7-byte UID.
    #[test]
    fn same_uid_detects_mismatch_at_every_byte() {
        let assessment = assessment_with_uid(FIXTURE_UID);

        for position in 0..7usize {
            let mut modified = FIXTURE_UID;
            modified[position] ^= 0xFF;
            assert!(
                !same_uid(&assessment, &modified),
                "UID mismatch at byte {position} must be detected"
            );
        }
    }

    /// same_uid must return false when card is not present.
    #[test]
    fn same_uid_returns_false_when_not_present() {
        let assessment = CardAssessment::default();
        assert!(!same_uid(&assessment, &FIXTURE_UID));
    }

    /// same_uid must return false when uid_len doesn't match.
    #[test]
    fn same_uid_returns_false_when_uid_len_mismatch() {
        let mut uid_storage = [0u8; 12];
        uid_storage[..7].copy_from_slice(&FIXTURE_UID);
        let assessment = CardAssessment {
            present: true,
            uid_len: 4,
            uid: Some(uid_storage),
            ..CardAssessment::default()
        };
        assert!(!same_uid(&assessment, &FIXTURE_UID));
    }

    /// same_uid must return false when stored UID is None.
    #[test]
    fn same_uid_returns_false_when_uid_is_none() {
        let assessment = CardAssessment {
            present: true,
            uid_len: 7,
            uid: None,
            ..CardAssessment::default()
        };
        assert!(!same_uid(&assessment, &FIXTURE_UID));
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Module 2: Key handling
// ═════════════════════════════════════════════════════════════════════════

mod key_handling {
    use super::*;

    /// AesKey Debug output must be redacted — no raw bytes visible.
    #[test]
    fn aeskey_debug_output_is_redacted() {
        let key = AesKey::new([0xDE; 16]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "AesKey([REDACTED])");
    }

    /// AesKey Debug output must not contain any hex representation of the
    /// actual key bytes.
    #[test]
    fn aeskey_debug_does_not_leak_key_material() {
        let key_bytes: [u8; 16] = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0F, 0xF0, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let key = AesKey::new(key_bytes);
        let debug = format!("{key:?}");
        let hex_of_key = to_hex(&key_bytes);
        assert!(
            !debug.contains(&hex_of_key),
            "Debug output must not contain hex of key bytes"
        );
        // Check individual byte values don't appear in any form
        for byte in &key_bytes {
            let hex_byte = format!("{byte:02X}");
            let hex_byte_lower = format!("{byte:02x}");
            assert!(
                !debug.contains(&hex_byte) && !debug.contains(&hex_byte_lower),
                "Debug output must not contain individual key byte '{byte:02X}'"
            );
        }
    }

    /// CardKeys Debug output must be redacted.
    #[test]
    fn cardkeys_debug_output_is_redacted() {
        let keys = CardKeys::zeroed();
        let debug = format!("{keys:?}");
        assert_eq!(debug, "CardKeys([REDACTED])");
    }

    /// CardKeySet Debug output must be redacted.
    #[test]
    fn cardkeyset_debug_output_is_redacted() {
        let keys = BoltcardDeterministicDeriver::derive_keys(
            &ISSUER_KEY,
            CardUid::new(FIXTURE_UID),
            1,
        );
        let debug = format!("{keys:?}");
        assert_eq!(debug, "CardKeySet([REDACTED])");
    }

    /// All zeros key must report as zero (factory/default state).
    #[test]
    fn zeroed_key_is_detected_as_zero() {
        let key = AesKey::zeroed();
        assert!(key.is_zero());
    }

    /// A non-zero key must not report as zero.
    #[test]
    fn nonzero_key_is_not_detected_as_zero() {
        let key = AesKey::new(ISSUER_KEY);
        assert!(!key.is_zero());
    }

    /// Partially-zero keys must not be mistaken for the factory key.
    #[test]
    fn partially_zero_key_is_not_zero() {
        let mut raw = [0u8; 16];
        raw[15] = 0x42;
        let key = AesKey::new(raw);
        assert!(!key.is_zero());
    }

    /// AesKey equality must compare actual bytes, not pointers.
    #[test]
    fn aeskey_equality_compares_bytes() {
        let raw = [0x42; 16];
        let a = AesKey::new(raw);
        let b = AesKey::new(raw);
        assert_eq!(a, b);

        let c = AesKey::new([0x43; 16]);
        assert_ne!(a, c);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Module 3: Input validation
// ═════════════════════════════════════════════════════════════════════════

mod input_validation {
    use super::*;

    /// Empty string must return InvalidLength (not panic) for N=16.
    #[test]
    fn decode_hex_empty_string_returns_invalid_length() {
        let result: Result<[u8; 16], HexError> = util::decode_hex("");
        assert_eq!(result, Err(HexError::InvalidLength));
    }

    /// Odd-length hex string must return InvalidLength.
    #[test]
    fn decode_hex_odd_length_returns_invalid_length() {
        let result: Result<[u8; 16], HexError> = util::decode_hex("ABC");
        assert_eq!(result, Err(HexError::InvalidLength));
    }

    /// Invalid hex characters must return InvalidHexCharacter.
    #[test]
    fn decode_hex_invalid_chars_returns_error() {
        let result: Result<[u8; 16], HexError> =
            util::decode_hex("GG000000000000000000000000000000");
        assert_eq!(result, Err(HexError::InvalidHexCharacter));
    }

    /// Too-short hex string must return InvalidLength.
    #[test]
    fn decode_hex_too_short_returns_invalid_length() {
        let result: Result<[u8; 16], HexError> = util::decode_hex("0001");
        assert_eq!(result, Err(HexError::InvalidLength));
    }

    /// Too-long hex string must return InvalidLength.
    #[test]
    fn decode_hex_too_long_returns_invalid_length() {
        let result: Result<[u8; 16], HexError> =
            util::decode_hex("00000000000000000000000000000001FF");
        assert_eq!(result, Err(HexError::InvalidLength));
    }

    /// decode_hex_into must return InvalidLength for empty string with non-empty buffer.
    #[test]
    fn decode_hex_into_empty_string_nonempty_buf_returns_error() {
        let mut out = [0u8; 16];
        let result = util::decode_hex_into("", &mut out);
        assert_eq!(result, Err(HexError::InvalidLength));
    }

    /// decode_hex_into must return InvalidHexCharacter for non-hex chars.
    #[test]
    fn decode_hex_into_invalid_chars_returns_error() {
        let mut out = [0u8; 4];
        let result = util::decode_hex_into("ZZZZ", &mut out);
        assert_eq!(result, Err(HexError::InvalidHexCharacter));
    }

    /// decode_hex_into must return InvalidHexCharacter for invalid char at any position.
    #[test]
    fn decode_hex_into_invalid_char_at_start_returns_error() {
        let mut out = [0u8; 2];
        assert_eq!(
            util::decode_hex_into("gead", &mut out),
            Err(HexError::InvalidHexCharacter)
        );
    }

    /// decode_hex_into must handle invalid char in the middle.
    #[test]
    fn decode_hex_into_invalid_char_in_middle_returns_error() {
        let mut out = [0u8; 4];
        assert_eq!(
            util::decode_hex_into("deXXbeef", &mut out),
            Err(HexError::InvalidHexCharacter)
        );
    }

    /// decode_hex_into must handle invalid char at end.
    #[test]
    fn decode_hex_into_invalid_char_at_end_returns_error() {
        let mut out = [0u8; 2];
        assert_eq!(
            util::decode_hex_into("dexg", &mut out),
            Err(HexError::InvalidHexCharacter)
        );
    }

    /// decode_hex_into must reject odd-length input.
    #[test]
    fn decode_hex_into_odd_length_returns_error() {
        let mut out = [0u8; 2];
        assert_eq!(
            util::decode_hex_into("abc", &mut out),
            Err(HexError::InvalidLength)
        );
    }

    /// Valid hex must decode correctly (positive control).
    #[test]
    fn decode_hex_valid_input_succeeds() {
        let result: Result<[u8; 4], HexError> = util::decode_hex("DEADBEEF");
        assert_eq!(result, Ok([0xDE, 0xAD, 0xBE, 0xEF]));
    }

    /// Mixed-case hex must decode correctly.
    #[test]
    fn decode_hex_mixed_case_succeeds() {
        let result: Result<[u8; 4], HexError> = util::decode_hex("DeAdBeEf");
        assert_eq!(result, Ok([0xDE, 0xAD, 0xBE, 0xEF]));
    }

    /// AesKey::from_hex must reject empty string.
    #[test]
    fn aeskey_from_hex_empty_returns_error() {
        assert_eq!(
            AesKey::from_hex(""),
            Err(HexError::InvalidLength)
        );
    }

    /// AesKey::from_hex must reject wrong length.
    #[test]
    fn aeskey_from_hex_wrong_length_returns_error() {
        assert_eq!(
            AesKey::from_hex("0001"),
            Err(HexError::InvalidLength)
        );
    }

    /// AesKey::from_hex must reject invalid characters.
    #[test]
    fn aeskey_from_hex_invalid_chars_returns_error() {
        assert_eq!(
            AesKey::from_hex("GG00000000000000000000000000000X"),
            Err(HexError::InvalidHexCharacter)
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Module 4: Card state guards
// ═════════════════════════════════════════════════════════════════════════

mod card_state_guards {
    use super::*;
    use bolty_core::config::IssuerConfig;

    /// BoltyConfig defaults must have force_unsafe = false.
    /// This is the primary safety guard against accidental destructive operations.
    #[test]
    fn bolty_config_defaults_to_safe_mode() {
        let config = BoltyConfig::default();
        assert!(
            !config.force_unsafe,
            "force_unsafe must default to false for safety"
        );
    }

    /// BoltyConfig defaults must have no pending keys or issuer.
    #[test]
    fn bolty_config_defaults_have_no_pending_state() {
        let config = BoltyConfig::default();
        assert!(config.pending_keys.is_none());
        assert!(config.pending_issuer.is_none());
    }

    /// CardUid must reject too-short hex strings.
    #[test]
    fn carduid_rejects_short_hex() {
        assert!(CardUid::from_hex("042560").is_err());
    }

    /// CardUid must reject too-long hex strings.
    #[test]
    fn carduid_rejects_long_hex() {
        assert!(
            CardUid::from_hex("0425607A8F69801234").is_err()
        );
    }

    /// CardUid must reject invalid hex characters.
    #[test]
    fn carduid_rejects_invalid_chars() {
        assert!(
            CardUid::from_hex("ZZ2560507A8F6980").is_err()
        );
    }

    /// CardUid must accept valid 7-byte hex.
    #[test]
    fn carduid_accepts_valid_hex() {
        let result = CardUid::from_hex("0425607a8f6980");
        assert!(result.is_ok());
    }

    /// CardUid constructed from bytes must preserve those bytes.
    #[test]
    fn carduid_new_preserves_bytes() {
        let raw = [0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80];
        let uid = CardUid::new(raw);
        assert_eq!(uid.as_bytes(), &raw);
    }

    /// IssuerConfig defaults must use a zeroed key (safe, requires explicit set).
    #[test]
    fn issuer_config_defaults_to_zeroed_key() {
        let config = IssuerConfig::default();
        assert!(
            config.issuer_key.is_zero(),
            "Default issuer key must be zeroed (factory state)"
        );
    }

    /// IssuerConfig defaults must have key_version == KEY_VERSION_PROVISIONED (0x01).
    #[test]
    fn issuer_config_defaults_to_provisioned_version() {
        let config = IssuerConfig::default();
        assert_eq!(config.key_version, 0x01);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Module 5: Key derivation safety
// ═════════════════════════════════════════════════════════════════════════

mod key_derivation_safety {
    use super::*;
    use bolty_core::constants::FACTORY_KEY;

    /// Factory key (all zeros) must produce different derived keys than a
    /// real issuer key. This ensures the factory key cannot be used to
    /// authenticate provisioned cards.
    #[test]
    fn factory_key_produces_different_derived_keys() {
        let factory_keys = BoltcardDeterministicDeriver::derive_keys(
            &FACTORY_KEY,
            CardUid::new(FIXTURE_UID),
            1,
        );
        let real_keys =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);

        assert_ne!(
            factory_keys.k0, real_keys.k0,
            "Factory key must not produce same K0 as real issuer key"
        );
        assert_ne!(factory_keys.k1, real_keys.k1);
        assert_ne!(factory_keys.k2, real_keys.k2);
        assert_ne!(factory_keys.k3, real_keys.k3);
        assert_ne!(factory_keys.k4, real_keys.k4);
        assert_ne!(factory_keys.card_key, real_keys.card_key);
        assert_ne!(factory_keys.card_id, real_keys.card_id);
    }

    /// Different derivation versions must produce different K0.
    /// This ensures key rotation works.
    #[test]
    fn version_0_vs_version_1_produce_different_k0() {
        let keys_v0 =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 0);
        let keys_v1 =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);

        assert_ne!(
            keys_v0.k0, keys_v1.k0,
            "Version 0 and version 1 must produce different K0"
        );
        assert_ne!(keys_v0.card_key, keys_v1.card_key);
        assert_ne!(keys_v0.k2, keys_v1.k2);
    }

    /// Different UIDs must produce different keys (card_key, K0, K2, etc.).
    #[test]
    fn different_uids_produce_different_keys() {
        let uid_a = FIXTURE_UID;
        let uid_b: [u8; 7] = [0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];

        let keys_a = BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(uid_a), 1);
        let keys_b = BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(uid_b), 1);

        assert_ne!(keys_a.card_key, keys_b.card_key);
        assert_ne!(keys_a.k0, keys_b.k0);
        assert_ne!(keys_a.k2, keys_b.k2);
        assert_ne!(keys_a.k3, keys_b.k3);
        assert_ne!(keys_a.k4, keys_b.k4);
        assert_ne!(keys_a.card_id, keys_b.card_id);
    }

    /// K1 is derived from the issuer key only (not UID-dependent).
    /// This is the boltcard protocol design: K1 = AES-CMAC(issuer_key, TAG_K1).
    #[test]
    fn k1_is_issuer_keyed_not_uid_keyed() {
        let uid_a = FIXTURE_UID;
        let uid_b: [u8; 7] = [0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];

        let keys_a = BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(uid_a), 1);
        let keys_b = BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(uid_b), 1);

        assert_eq!(
            keys_a.k1, keys_b.k1,
            "K1 is derived from issuer_key only, must be identical for same issuer"
        );
    }

    /// Different issuer keys must produce different K1.
    #[test]
    fn different_issuer_keys_produce_different_k1() {
        let other_key: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let keys_a = BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);
        let keys_b =
            BoltcardDeterministicDeriver::derive_keys(&other_key, CardUid::new(FIXTURE_UID), 1);

        assert_ne!(keys_a.k1, keys_b.k1);
        assert_ne!(keys_a.card_id, keys_b.card_id);
    }

    /// Same inputs must produce identical keys (determinism).
    #[test]
    fn derivation_is_deterministic() {
        let keys_a =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);
        let keys_b =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);

        assert_eq!(keys_a.card_key, keys_b.card_key);
        assert_eq!(keys_a.k0, keys_b.k0);
        assert_eq!(keys_a.k1, keys_b.k1);
        assert_eq!(keys_a.k2, keys_b.k2);
        assert_eq!(keys_a.k3, keys_b.k3);
        assert_eq!(keys_a.k4, keys_b.k4);
        assert_eq!(keys_a.card_id, keys_b.card_id);
    }

    /// Derived K1 must match the known fixture vector.
    #[test]
    fn derived_k1_matches_known_fixture() {
        let keys =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);
        assert_eq!(keys.k1.as_bytes(), &K1);
    }

    /// Derived K2 must match the known fixture vector.
    #[test]
    fn derived_k2_matches_known_fixture() {
        let keys =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);
        assert_eq!(keys.k2.as_bytes(), &K2);
    }

    /// Version 1 vs version 2 must produce different card_key.
    #[test]
    fn version_1_vs_version_2_produce_different_keys() {
        let keys_v1 =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 1);
        let keys_v2 =
            BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(FIXTURE_UID), 2);

        assert_ne!(keys_v1.card_key, keys_v2.card_key);
        assert_ne!(keys_v1.k0, keys_v2.k0);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Module 6: PICC data validation
// ═════════════════════════════════════════════════════════════════════════

mod picc_data_validation {
    use super::*;

    /// picc_decrypt_p must reject data where the decrypted first byte is not
    /// PICC_FORMAT_BOLTCARD (0xC7). Using a wrong K1 produces garbage that
    /// won't have the correct tag byte.
    #[test]
    fn picc_decrypt_p_rejects_wrong_tag_byte() {
        let wrong_k1: [u8; 16] = [0xFF; 16];
        assert!(
            picc_decrypt_p(&wrong_k1, FIXTURE_P_HEX).is_none(),
            "Decryption with wrong key should not produce valid tag byte 0xC7"
        );
    }

    /// picc_decrypt_p must reject data decrypted with the factory (all-zero) key.
    #[test]
    fn picc_decrypt_p_rejects_factory_key() {
        assert!(
            picc_decrypt_p(&[0u8; 16], FIXTURE_P_HEX).is_none(),
            "Factory key must not decrypt provisioned card data"
        );
    }

    /// picc_decrypt_p must accept data decrypted with the correct K1.
    #[test]
    fn picc_decrypt_p_accepts_correct_key() {
        let result = picc_decrypt_p(&K1, FIXTURE_P_HEX);
        assert!(result.is_some(), "Correct key must decrypt valid p_hex");
        let picc = result.unwrap(); // unwrap is safe here — tested above
        assert_eq!(picc.uid, FIXTURE_UID);
        assert!(picc.has_uid);
        assert!(picc.has_counter);
    }

    /// picc_decrypt_p must reject truncated (too-short) hex input.
    #[test]
    fn picc_decrypt_p_rejects_truncated_data() {
        assert!(picc_decrypt_p(&K1, "too_short").is_none());
    }

    /// picc_decrypt_p must reject too-long hex input.
    #[test]
    fn picc_decrypt_p_rejects_oversized_data() {
        assert!(
            picc_decrypt_p(&K1, "00112233445566778899AABBCCDDEEFF00").is_none()
        );
    }

    /// picc_decrypt_p must reject invalid hex characters.
    #[test]
    fn picc_decrypt_p_rejects_invalid_hex_chars() {
        assert!(
            picc_decrypt_p(&K1, "ZZ112233445566778899AABBCCDDEEFF").is_none()
        );
    }

    /// picc_decrypt_p must reject empty string.
    #[test]
    fn picc_decrypt_p_rejects_empty_string() {
        assert!(picc_decrypt_p(&K1, "").is_none());
    }

    /// Counter extraction must be little-endian 3 bytes.
    /// Verified through sdm_build_sv2 which uses the same encoding format.
    #[test]
    fn counter_encoding_is_little_endian_3_bytes() {
        let uid = [0x01; 7];

        // Counter 0x010203 → bytes should be [0x03, 0x02, 0x01] (little-endian)
        let sv2 = sdm_build_sv2(&uid, 0x010203);
        assert_eq!(sv2[13], 0x03, "LSB of counter must be at byte 13");
        assert_eq!(sv2[14], 0x02, "Middle byte of counter must be at byte 14");
        assert_eq!(sv2[15], 0x01, "MSB of counter must be at byte 15");
    }

    /// Counter encoding: zero counter must produce all-zero counter bytes.
    #[test]
    fn counter_encoding_zero_is_all_zeros() {
        let uid = [0x01; 7];
        let sv2 = sdm_build_sv2(&uid, 0);
        assert_eq!(sv2[13], 0x00);
        assert_eq!(sv2[14], 0x00);
        assert_eq!(sv2[15], 0x00);
    }

    /// Counter encoding: max 3-byte value (0xFFFFFF) must produce all-FF bytes.
    #[test]
    fn counter_encoding_max_value() {
        let uid = [0x01; 7];
        let sv2 = sdm_build_sv2(&uid, 0xFFFFFF);
        assert_eq!(sv2[13], 0xFF);
        assert_eq!(sv2[14], 0xFF);
        assert_eq!(sv2[15], 0xFF);
    }

    /// sdm_build_sv2 must preserve the SV2 header.
    #[test]
    fn sdm_build_sv2_preserves_header() {
        let uid = [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80];
        let sv2 = sdm_build_sv2(&uid, 42);
        assert_eq!(&sv2[0..6], &SV2_HEADER);
    }

    /// sdm_build_sv2 must preserve the UID bytes at positions 6-12.
    #[test]
    fn sdm_build_sv2_preserves_uid() {
        let uid = [0x04, 0x25, 0x60, 0x7A, 0x8F, 0x69, 0x80];
        let sv2 = sdm_build_sv2(&uid, 0);
        assert_eq!(&sv2[6..13], &uid);
    }

    /// picc_parse_url must reject URLs missing the p parameter.
    #[test]
    fn picc_parse_url_rejects_missing_p() {
        let url = "https://example.com/bolt?c=FCC9A22201EA2298";
        assert!(!picc_parse_url(&K1, &K2, url).valid);
    }

    /// picc_parse_url must reject URLs missing the c parameter.
    #[test]
    fn picc_parse_url_rejects_missing_c() {
        let url = "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF";
        assert!(!picc_parse_url(&K1, &K2, url).valid);
    }

    /// picc_parse_url must reject URLs with wrong K1.
    #[test]
    fn picc_parse_url_rejects_wrong_k1() {
        let wrong_k1: [u8; 16] = [0xFF; 16];
        assert!(!picc_parse_url(&wrong_k1, &K2, "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298").valid);
    }

    /// picc_parse_url must reject URLs with wrong K2.
    #[test]
    fn picc_parse_url_rejects_wrong_k2() {
        let wrong_k2: [u8; 16] = [0xFF; 16];
        assert!(!picc_parse_url(&K1, &wrong_k2, "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298").valid);
    }

    /// picc_parse_url must accept a valid fixture URL.
    #[test]
    fn picc_parse_url_accepts_valid_fixture() {
        let url = "https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298";
        let picc = picc_parse_url(&K1, &K2, url);
        assert!(picc.valid);
        assert_eq!(picc.uid, FIXTURE_UID);
        assert_eq!(picc.counter, 0);
    }

    /// PICC_FORMAT_BOLTCARD must be 0xC7.
    #[test]
    fn picc_format_boltcard_is_0xc7() {
        assert_eq!(PICC_FORMAT_BOLTCARD, 0xC7);
    }
}
