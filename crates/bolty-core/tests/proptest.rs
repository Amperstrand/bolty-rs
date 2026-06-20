//! Property-based tests for bolty-core cryptographic primitives.
//!
//! Uses `proptest` to generate random inputs and verify invariants that must
//! hold for ALL valid inputs, not just a handful of hand-picked test vectors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use bolty_core::{
    crypto::aes_cmac,
    derivation::BoltcardDeterministicDeriver,
    picc::{PICC_FORMAT_BOLTCARD, SV2_HEADER, picc_decrypt_p, sdm_build_sv2},
    uid::CardUid,
    util::{decode_hex, decode_hex_into, encode_hex},
};
use proptest::prelude::*;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Encrypt a single 16-byte block with AES-128-CBC using a zero IV.
///
/// With a zero IV, CBC encryption of one block is identical to ECB encryption.
/// This replicates the card-side PICC data encryption used by `picc_decrypt_p`.
fn aes_cbc_encrypt_zero_iv(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::Aes128;
    use aes::cipher::{Array, Block, BlockCipherEncrypt, KeyInit};
    let cipher = Aes128::new(&Array::from(*key));
    let mut blk = Block::<Aes128>::default();
    blk.copy_from_slice(block);
    // CBC with zero IV: XOR with zeros (no-op), then encrypt.
    cipher.encrypt_block(&mut blk);
    block.copy_from_slice(&blk);
}

/// Build a valid PICC plaintext, encrypt it with K1, and return hex-encoded ciphertext.
fn build_valid_picc_p_hex(k1: &[u8; 16], uid: &[u8; 7], counter: u32) -> String {
    let mut plaintext = [0u8; 16];
    plaintext[0] = PICC_FORMAT_BOLTCARD; // 0xC7: format tag with UID+counter flags
    plaintext[1..8].copy_from_slice(uid);
    plaintext[8] = counter as u8;
    plaintext[9] = (counter >> 8) as u8;
    plaintext[10] = (counter >> 16) as u8;
    // bytes 11–15 remain zero (padding)
    aes_cbc_encrypt_zero_iv(k1, &mut plaintext);
    encode_hex(&plaintext)
}

proptest! {
    // ═══ 1. AES-CMAC roundtrip ═══════════════════════════════════════════════
    // A freshly computed CMAC is deterministic: recomputing the CMAC of the
    // same key + message always yields the identical 16-byte tag.
    #[test]
    fn aes_cmac_roundtrip(
        key in prop::array::uniform16(any::<u8>()),
        msg in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mac1 = aes_cmac(&key, &msg);
        let mac2 = aes_cmac(&key, &msg);

        prop_assert_eq!(mac1.len(), 16);
        prop_assert_eq!(mac1, mac2);
    }

    // ═══ 1b. AES-CMAC key sensitivity ═════════════════════════════════════════
    // Different keys must produce different CMACs for the same non-empty message.
    #[test]
    fn aes_cmac_key_sensitivity(
        key1 in prop::array::uniform16(any::<u8>()),
        key2 in prop::array::uniform16(any::<u8>()),
        msg in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(key1 != key2);

        let mac1 = aes_cmac(&key1, &msg);
        let mac2 = aes_cmac(&key2, &msg);

        prop_assert_ne!(mac1, mac2);
    }

    // ═══ 2. Key derivation determinism ════════════════════════════════════════
    // derive_keys is a pure function: identical inputs always produce identical
    // output across repeated calls.
    #[test]
    fn key_derivation_determinism(
        issuer in prop::array::uniform16(any::<u8>()),
        uid in prop::array::uniform7(any::<u8>()),
        version in 0u32..=255,
    ) {
        let card_uid = CardUid::new(uid);

        let keys1 = BoltcardDeterministicDeriver::derive_keys(&issuer, card_uid, version);
        let keys2 = BoltcardDeterministicDeriver::derive_keys(&issuer, card_uid, version);

        prop_assert_eq!(keys1.card_key, keys2.card_key);
        prop_assert_eq!(keys1.k0, keys2.k0);
        prop_assert_eq!(keys1.k1, keys2.k1);
        prop_assert_eq!(keys1.k2, keys2.k2);
        prop_assert_eq!(keys1.k3, keys2.k3);
        prop_assert_eq!(keys1.k4, keys2.k4);
        prop_assert_eq!(keys1.card_id, keys2.card_id);
    }

    // ═══ 3. Key derivation uniqueness ═════════════════════════════════════════
    // Different UIDs must produce different UID-dependent keys (card_key, K0,
    // K2, K3, K4, card_id). K1 is derived solely from the issuer key, so it is
    // identical regardless of UID.
    #[test]
    fn key_derivation_uniqueness(
        issuer in prop::array::uniform16(any::<u8>()),
        uid1 in prop::array::uniform7(any::<u8>()),
        uid2 in prop::array::uniform7(any::<u8>()),
        version in 0u32..=255,
    ) {
        prop_assume!(uid1 != uid2);

        let keys1 = BoltcardDeterministicDeriver::derive_keys(
            &issuer,
            CardUid::new(uid1),
            version,
        );
        let keys2 = BoltcardDeterministicDeriver::derive_keys(
            &issuer,
            CardUid::new(uid2),
            version,
        );

        // UID-dependent keys must differ.
        prop_assert_ne!(keys1.card_key, keys2.card_key);
        prop_assert_ne!(keys1.k0, keys2.k0);
        prop_assert_ne!(keys1.k2, keys2.k2);
        prop_assert_ne!(keys1.k3, keys2.k3);
        prop_assert_ne!(keys1.k4, keys2.k4);
        prop_assert_ne!(keys1.card_id, keys2.card_id);

        // K1 depends only on the issuer key — must be identical.
        prop_assert_eq!(keys1.k1, keys2.k1);
    }

    // ═══ 4. Hex encoding roundtrip (variable length) ═════════════════════════
    // encode_hex followed by decode_hex_into recovers the original bytes for
    // any byte sequence.
    #[test]
    fn hex_roundtrip_variable(
        bytes in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let encoded = encode_hex(&bytes);
        let mut decoded = vec![0u8; bytes.len()];
        decode_hex_into(&encoded, &mut decoded).unwrap();
        prop_assert_eq!(decoded, bytes);
    }

    // ═══ 4b. Hex encoding roundtrip (fixed 16-byte) ══════════════════════════
    // Specifically exercises the generic decode_hex::<16> path used by AesKey.
    #[test]
    fn hex_roundtrip_fixed_16(
        key in prop::array::uniform16(any::<u8>()),
    ) {
        let encoded = encode_hex(&key);
        let decoded = decode_hex::<16>(&encoded).unwrap();
        prop_assert_eq!(decoded, key);
    }

    // ═══ 5. PICC decrypt consistency ══════════════════════════════════════════
    // picc_decrypt_p with the correct K1 always recovers valid PICCData:
    // 0xC7 format tag, correct UID, and correct counter.
    #[test]
    fn picc_decrypt_consistency(
        k1 in prop::array::uniform16(any::<u8>()),
        uid in prop::array::uniform7(any::<u8>()),
        counter in 0u32..=0xFFFFFF,
    ) {
        let p_hex = build_valid_picc_p_hex(&k1, &uid, counter);

        let picc_opt = picc_decrypt_p(&k1, &p_hex);
        prop_assert!(picc_opt.is_some(), "picc_decrypt_p must succeed with correct K1");

        let picc = picc_opt.unwrap();
        prop_assert!(picc.has_uid);
        prop_assert!(picc.has_counter);
        prop_assert_eq!(picc.uid, uid);
        prop_assert_eq!(picc.counter, counter);
    }

    // ═══ 6. SV2 derivation ════════════════════════════════════════════════════
    // sdm_build_sv2 always produces a 16-byte block with the correct header,
    // UID copy, and little-endian 3-byte counter.
    #[test]
    fn sdm_build_sv2_structure(
        uid in prop::array::uniform7(any::<u8>()),
        counter in 0u32..=0xFFFFFF,
    ) {
        let sv2 = sdm_build_sv2(&uid, counter);

        prop_assert_eq!(sv2.len(), 16);
        prop_assert_eq!(&sv2[0..6], &SV2_HEADER[..]);
        prop_assert_eq!(&sv2[6..13], &uid[..]);
        prop_assert_eq!(sv2[13], counter as u8);
        prop_assert_eq!(sv2[14], (counter >> 8) as u8);
        prop_assert_eq!(sv2[15], (counter >> 16) as u8);
    }
}
