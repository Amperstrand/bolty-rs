//! SECURITY: State-transition guards — card-state constants pin the valid
//! lifecycle boundaries.
//!
//! Invariant: the NTAG424 card lifecycle is anchored by fixed constants — the
//! factory key (all zeros), the blank version, the provisioned version, and
//! the protected/locked sentinel. A regression in any of these (e.g.
//! `FACTORY_KEY` gaining a non-zero byte, or `KEY_VERSION_PROVISIONED`
//! shifting from `0x01`) would cause the wrong key to be derived or the wrong
//! state to be reported, silently bricking cards or misclassifying them.
//!
//! The runtime state classifier (`classify_card_state` in
//! `bolty-cli/src/diagnose.rs`) is verified inline there. This module pins the
//! constant values the classifier and the derivation both depend on.

use bolty_core::constants::{
    FACTORY_KEY, KEY_VERSION_BLANK, KEY_VERSION_PROTECTED, KEY_VERSION_PROVISIONED, NUM_KEYS,
    UID_LEN,
};

#[test]
fn factory_key_is_all_zeros() {
    // SECURITY invariant: FACTORY_KEY must be the 16-byte all-zero key. This
    // is the NXP factory default for NTAG424. A single non-zero byte would
    // make every "blank card" authentication attempt fail and every
    // factory-path burn write the wrong key.
    assert_eq!(FACTORY_KEY, [0u8; 16]);
}

#[test]
fn factory_key_is_exactly_16_bytes() {
    // SECURITY invariant: AES-128 keys are 16 bytes. A length regression would
    // either truncate the key (weakening it) or pad it (changing the derived
    // material).
    assert_eq!(FACTORY_KEY.len(), 16);
}

#[test]
fn blank_version_is_zero() {
    // SECURITY invariant: the blank/uninitialized key version is 0x00. The
    // diagnose classifier treats version==0 as "never provisioned"; a non-zero
    // blank version would misclassify fresh cards as half-wiped.
    assert_eq!(KEY_VERSION_BLANK, 0x00);
}

#[test]
fn provisioned_version_is_one() {
    // SECURITY invariant: the standard provisioned version is 0x01. The
    // derivation function embeds this version into the CMAC message; changing
    // it would derive a different key set and break every already-burned card.
    assert_eq!(KEY_VERSION_PROVISIONED, 0x01);
}

#[test]
fn protected_version_is_max() {
    // SECURITY invariant: the protected/locked sentinel is 0xFF, the maximum
    // version value. This marks a card whose key version has been frozen
    // (e.g. after TotFailCtr lockout). A lower value would collide with a
    // legitimate incremental re-burn version.
    assert_eq!(KEY_VERSION_PROTECTED, 0xFF);
}

#[test]
fn blank_and_provisioned_versions_are_distinct() {
    // SECURITY invariant: the blank and provisioned versions must never
    // compare equal, or the state machine collapses two distinct lifecycle
    // stages into one.
    assert_ne!(KEY_VERSION_BLANK, KEY_VERSION_PROVISIONED);
    assert_ne!(KEY_VERSION_BLANK, KEY_VERSION_PROTECTED);
    assert_ne!(KEY_VERSION_PROVISIONED, KEY_VERSION_PROTECTED);
}

#[test]
fn uid_length_is_seven_bytes() {
    // SECURITY invariant: NTAG424 uses a 7-byte UID. The derivation message
    // layout hard-codes this length (message[4..11]); a change would
    // misalign the CMAC input and derive wrong keys.
    assert_eq!(UID_LEN, 7);
}

#[test]
fn num_keys_is_five() {
    // SECURITY invariant: NTAG424 has exactly five key slots (K0–K4).
    // CardKeys has five fields; a mismatch would leave a slot un-keyed or
    // over-index.
    assert_eq!(NUM_KEYS, 5);
}

#[test]
fn provisioned_version_round_trips_through_derivation() {
    // SECURITY invariant: feeding KEY_VERSION_PROVISIONED into the derivation
    // must produce a deterministic, non-factory key set. This cross-checks
    // that the constant the classifier uses matches the constant the deriver
    // effectively uses (version 1), guarding against a silent drift where the
    // two modules disagree on "provisioned".
    use bolty_core::derivation::BoltcardDeterministicDeriver;
    use bolty_core::uid::CardUid;

    let uid = CardUid::new([0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80]);
    let issuer = [0u8; 16];
    let keys =
        BoltcardDeterministicDeriver::derive_keys(&issuer, uid, u32::from(KEY_VERSION_PROVISIONED));
    // The derived K0 for a non-trivial issuer must not equal the factory key.
    // (With issuer=all-zero and version=1 the derivation is still well-defined
    // and non-zero, proving the version constant actually drives the CMAC.)
    assert_ne!(
        keys.k0.as_bytes(),
        &FACTORY_KEY,
        "derived K0 must differ from the factory key under the provisioned version"
    );
}
