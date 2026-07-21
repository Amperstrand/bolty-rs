//! Property-based tests for bolty-core crypto primitives.
//!
//! Exercises AES-128-CMAC, deterministic key derivation, hex encoding,
//! PICC SDM CMAC verification, and `AesKey` debug redaction using
//! [`proptest`](https://docs.rs/proptest). Each property runs 256 cases by
//! default (proptest's `PROPTEST_CASES`).
//!
//! Run with: `cargo test -p bolty-core --test proptest_crypto`
//!
//! Design notes:
//! * No `unwrap`/`expect`/`panic` — only `prop_assert*!` / `prop_assume!`.
//! * No dynamic indexing (workspace `clippy::indexing_slicing = "warn"`,
//!   enforced as `-D warnings`); only constant array indices are used.
//! * `AesKey`/`CardKeySet` implement `Drop` (zeroize) and are non-`Copy`, so
//!   keys are compared by reference via `AesKey::as_bytes()` and never moved.
//! * `k1` is derived from the issuer key alone (`aes_cmac(ik, TAG_K1)`), so it
//!   is intentionally *not* asserted to differ across UIDs/versions.

use bolty_core::crypto::aes_cmac;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc::{PiccData, picc_verify_c, sdm_build_sv2};
use bolty_core::secret::AesKey;
use bolty_core::uid::CardUid;
use bolty_core::util::{decode_hex_into, encode_hex};

use proptest::prelude::*;

// ════════════════════════════════════════════════════════════════════════
// (a) Key derivation determinism
// ════════════════════════════════════════════════════════════════════════
proptest! {
    /// Deriving keys twice from identical (issuer_key, uid, version) inputs
    /// must produce byte-identical `CardKeySet`s — every key + the card_id.
    #[test]
    fn key_derivation_deterministic(
        ik in any::<[u8; 16]>(),
        uid in any::<[u8; 7]>(),
        version in 0u32..=255,
    ) {
        let uid = CardUid::new(uid);
        let set1 = BoltcardDeterministicDeriver::derive_keys(&ik, uid, version);
        let set2 = BoltcardDeterministicDeriver::derive_keys(&ik, uid, version);

        // CardKeySet derives PartialEq; compare by reference (it is non-Copy).
        prop_assert_eq!(&set1, &set2);
        // Belt-and-suspenders: each field individually, via key bytes.
        prop_assert_eq!(set1.card_key.as_bytes(), set2.card_key.as_bytes());
        prop_assert_eq!(set1.k0.as_bytes(), set2.k0.as_bytes());
        prop_assert_eq!(set1.k1.as_bytes(), set2.k1.as_bytes());
        prop_assert_eq!(set1.k2.as_bytes(), set2.k2.as_bytes());
        prop_assert_eq!(set1.k3.as_bytes(), set2.k3.as_bytes());
        prop_assert_eq!(set1.k4.as_bytes(), set2.k4.as_bytes());
        prop_assert_eq!(&set1.card_id, &set2.card_id);
    }
}

// ════════════════════════════════════════════════════════════════════════
// (b) Key derivation uniqueness (overwhelming probability; CMAC is a PRF)
// ════════════════════════════════════════════════════════════════════════
proptest! {
    /// Different UIDs (same issuer key + version) must yield different
    /// card_key, k0, k2, k3, k4 and card_id. k1 is intentionally excluded —
    /// it depends only on the issuer key.
    #[test]
    fn different_uids_different_keys(
        ik in any::<[u8; 16]>(),
        uid1 in any::<[u8; 7]>(),
        uid2 in any::<[u8; 7]>(),
        version in 0u32..=255,
    ) {
        prop_assume!(uid1 != uid2);

        let set1 = BoltcardDeterministicDeriver::derive_keys(&ik, CardUid::new(uid1), version);
        let set2 = BoltcardDeterministicDeriver::derive_keys(&ik, CardUid::new(uid2), version);

        prop_assert_ne!(set1.card_key.as_bytes(), set2.card_key.as_bytes());
        prop_assert_ne!(set1.k0.as_bytes(), set2.k0.as_bytes());
        prop_assert_ne!(set1.k2.as_bytes(), set2.k2.as_bytes());
        prop_assert_ne!(set1.k3.as_bytes(), set2.k3.as_bytes());
        prop_assert_ne!(set1.k4.as_bytes(), set2.k4.as_bytes());
        prop_assert_ne!(&set1.card_id, &set2.card_id);
    }

    /// Same UID + issuer key but different versions must yield different
    /// card_key (and the keys derived from it: k0, k2, k3, k4).
    #[test]
    fn different_versions_different_card_key(
        ik in any::<[u8; 16]>(),
        uid in any::<[u8; 7]>(),
        v1 in 0u32..=255,
        v2 in 0u32..=255,
    ) {
        prop_assume!(v1 != v2);

        let uid = CardUid::new(uid);
        let set1 = BoltcardDeterministicDeriver::derive_keys(&ik, uid, v1);
        let set2 = BoltcardDeterministicDeriver::derive_keys(&ik, uid, v2);

        prop_assert_ne!(set1.card_key.as_bytes(), set2.card_key.as_bytes());
        prop_assert_ne!(set1.k0.as_bytes(), set2.k0.as_bytes());
        prop_assert_ne!(set1.k2.as_bytes(), set2.k2.as_bytes());
        prop_assert_ne!(set1.k3.as_bytes(), set2.k3.as_bytes());
        prop_assert_ne!(set1.k4.as_bytes(), set2.k4.as_bytes());
    }

    /// Different issuer keys (same UID + version) must yield different keys
    /// across the board — every derived value is keyed off the issuer key.
    #[test]
    fn different_issuer_keys_different_keys(
        ik1 in any::<[u8; 16]>(),
        ik2 in any::<[u8; 16]>(),
        uid in any::<[u8; 7]>(),
        version in 0u32..=255,
    ) {
        prop_assume!(ik1 != ik2);

        let uid = CardUid::new(uid);
        let set1 = BoltcardDeterministicDeriver::derive_keys(&ik1, uid, version);
        let set2 = BoltcardDeterministicDeriver::derive_keys(&ik2, uid, version);

        prop_assert_ne!(set1.card_key.as_bytes(), set2.card_key.as_bytes());
        prop_assert_ne!(set1.k0.as_bytes(), set2.k0.as_bytes());
        prop_assert_ne!(set1.k1.as_bytes(), set2.k1.as_bytes());
        prop_assert_ne!(&set1.card_id, &set2.card_id);
    }
}

// ════════════════════════════════════════════════════════════════════════
// (c) Hex encoding round-trip
// ════════════════════════════════════════════════════════════════════════
proptest! {
    /// `from_hex(to_hex(bytes)) == bytes` for all byte arrays of length 0..100.
    #[test]
    fn hex_roundtrip(data in prop::collection::vec(any::<u8>(), 0..100)) {
        let encoded = encode_hex(&data);
        let mut decoded = vec![0u8; data.len()];

        let res = decode_hex_into(&encoded, &mut decoded);
        prop_assert!(res.is_ok(), "decode_hex_into failed on own output: {:?}", res);
        prop_assert_eq!(decoded, data);
    }

    /// The hex decoder is case-insensitive, so uppercasing the encoded form
    /// must still round-trip back to the original bytes.
    #[test]
    fn hex_uppercase_decodes_roundtrip(data in prop::collection::vec(any::<u8>(), 0..100)) {
        let encoded_upper = encode_hex(&data).to_uppercase();
        let mut decoded = vec![0u8; data.len()];

        let res = decode_hex_into(&encoded_upper, &mut decoded);
        prop_assert!(res.is_ok(), "decode_hex_into failed on uppercase: {:?}", res);
        prop_assert_eq!(decoded, data);
    }

    /// A corrupted hex string (first nibble replaced by 'g') must be rejected.
    #[test]
    fn hex_corrupted_char_is_rejected(data in prop::collection::vec(any::<u8>(), 1..50)) {
        let mut bad = encode_hex(&data);
        // Replace the first character with an invalid hex char 'g'.
        bad.replace_range(0..1, "g");
        let mut decoded = vec![0u8; data.len()];

        let res = decode_hex_into(&bad, &mut decoded);
        prop_assert!(res.is_err(), "decoder accepted invalid hex char");
    }
}

// ════════════════════════════════════════════════════════════════════════
// (d) AesKey Debug redaction — never leaks key material
// ════════════════════════════════════════════════════════════════════════
proptest! {
    #[test]
    fn aeskey_debug_never_leaks(key_bytes in any::<[u8; 16]>()) {
        let key = AesKey::new(key_bytes);
        let debug_str = format!("{:?}", key);

        // Debug output is the constant redaction marker (compare without moving).
        prop_assert!(
            debug_str.as_str() == "AesKey([REDACTED])",
            "AesKey Debug leaked: {debug_str}"
        );

        // Belt-and-suspenders: the full key material (as a 32-char lowercase
        // hex string) must never appear anywhere in the Debug output.
        let material: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();
        prop_assert!(
            !debug_str.contains(&material),
            "key material leaked into Debug: {debug_str}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════
// (e) Derived keys are always non-zero (CMAC of a real input is non-zero w.p.
//     1 - 2^-128; over 256 cases this is cryptographically certain).
// ════════════════════════════════════════════════════════════════════════
proptest! {
    #[test]
    fn derived_keys_nonzero(
        ik in any::<[u8; 16]>(),
        uid in any::<[u8; 7]>(),
        version in 0u32..=255,
    ) {
        let uid = CardUid::new(uid);
        let set = BoltcardDeterministicDeriver::derive_keys(&ik, uid, version);

        prop_assert!(!set.card_key.is_zero(), "card_key was all-zero");
        prop_assert!(!set.k0.is_zero(), "k0 was all-zero");
        prop_assert!(!set.k1.is_zero(), "k1 was all-zero");
        prop_assert!(!set.k2.is_zero(), "k2 was all-zero");
        prop_assert!(!set.k3.is_zero(), "k3 was all-zero");
        prop_assert!(!set.k4.is_zero(), "k4 was all-zero");
        prop_assert!(set.card_id != [0u8; 16], "card_id was all-zero");
    }
}

// ════════════════════════════════════════════════════════════════════════
// CMAC verification round-trip
//   * legitimate tag recomputes identically,
//   * a single-bit flip in the message produces a different tag (avalanche).
// ════════════════════════════════════════════════════════════════════════
proptest! {
    /// The CMAC of a fixed (key, message) is deterministic: recomputing it
    /// yields the identical 16-byte tag.
    #[test]
    fn cmac_recomputation_matches(
        key in any::<[u8; 16]>(),
        msg in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mac1 = aes_cmac(&key, &msg);
        let mac2 = aes_cmac(&key, &msg);
        prop_assert_eq!(mac1, mac2);
    }

    /// Flipping exactly one bit of the message (first byte) must change the
    /// resulting CMAC tag — CMAC's avalanche property.
    #[test]
    fn cmac_single_bit_flip_in_message_changes_tag(
        key in any::<[u8; 16]>(),
        first_byte in any::<u8>(),
        rest in prop::collection::vec(any::<u8>(), 0..63),
        bit_idx in 0u8..8,
    ) {
        let flipped_first = first_byte ^ (1u8 << bit_idx);

        let original: Vec<u8> = core::iter::once(first_byte)
            .chain(rest.iter().copied())
            .collect();
        let tampered: Vec<u8> = core::iter::once(flipped_first)
            .chain(rest.iter().copied())
            .collect();

        let mac_orig = aes_cmac(&key, &original);
        let mac_tamp = aes_cmac(&key, &tampered);
        prop_assert_ne!(mac_orig, mac_tamp);
    }
}

// ════════════════════════════════════════════════════════════════════════
// PICC SDM CMAC verification round-trip
//
// bolty-core exposes `picc_decrypt_p` (the P-decrypt path) publicly, but the
// matching AES-CBC *encrypt* path is `#[cfg(test)]`-gated inside `picc.rs`
// and therefore unreachable from an integration test. A full P encrypt→decrypt
// round-trip is consequently not possible using the public API, so we instead
// round-trip the SDM `c` (CMAC) parameter, which is fully public:
// `sdm_build_sv2` + `aes_cmac` + `picc_verify_c`.
// ════════════════════════════════════════════════════════════════════════
proptest! {
    /// For any (k2, uid, counter): the legitimate `c` value verifies, and a
    /// single-bit flip of `c` fails verification.
    #[test]
    fn picc_cmac_verification_roundtrip(
        k2 in any::<[u8; 16]>(),
        uid in any::<[u8; 7]>(),
        counter in 0u32..=0x00FF_FFFF,
    ) {
        let picc = PiccData {
            valid: false,
            uid,
            counter,
            has_uid: true,
            has_counter: true,
        };

        // Reproduce the public SDM MAC computation (see picc::picc_verify_c).
        let sv2 = sdm_build_sv2(&picc.uid, picc.counter);
        let derived_key = aes_cmac(&k2, &sv2);
        let full_mac = aes_cmac(&derived_key, &[]);

        // c = the odd-indexed bytes of full_mac (matches picc::truncate_odd_bytes).
        // Only constant array indices are used here.
        let c_bytes: [u8; 8] = [
            full_mac[1], full_mac[3], full_mac[5], full_mac[7],
            full_mac[9], full_mac[11], full_mac[13], full_mac[15],
        ];
        let c_hex = encode_hex(&c_bytes);

        // Legitimate MAC must verify.
        prop_assert!(
            picc_verify_c(&k2, &picc, &c_hex),
            "legitimate c value failed to verify"
        );

        // A single-bit flip of the first byte of c must fail verification.
        let bad_first = c_bytes[0] ^ 0x01;
        let bad_bytes: [u8; 8] = [
            bad_first, c_bytes[1], c_bytes[2], c_bytes[3],
            c_bytes[4], c_bytes[5], c_bytes[6], c_bytes[7],
        ];
        let bad_hex = encode_hex(&bad_bytes);
        prop_assert!(
            !picc_verify_c(&k2, &picc, &bad_hex),
            "tampered c value unexpectedly verified"
        );
    }
}
