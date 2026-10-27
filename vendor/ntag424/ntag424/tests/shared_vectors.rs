// SPDX-FileCopyrightText: 2026 Amperstrand
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Shared cross-language vector suite from
//! <https://github.com/Amperstrand/ntag424-vectors> (vendored
//! `vectors.json`, byte-identical to the canonical file).
//!
//! Runs every vector the crate's PUBLIC API can express:
//!
//! - `picc_decrypt` — via `sdm::Verifier::decrypt_picc_data` (AES mode,
//!   encrypted PICC mirror): asserts UID and the raw SDMReadCtr bytes.
//! - `sun_mac` — via `sdm::Verifier::verify` with plain UID/counter
//!   mirrors and an empty MAC input window (AN12196 §3.4.4.2.1 chain:
//!   SV2 → session key → CMAC → truncation).
//! - `sdm_full` — via `sdm::Verifier::verify_with_meta_key` (K1 as
//!   `SDMMetaRead`, K2 as `SDMFileRead`) plus `decrypt_picc_data`.
//!
//! Categories the public API cannot express (skipped, counted by the
//! `suite_accounting` test):
//!
//! - `aes_cmac` (5: RFC 4493 Examples 3+4, AN12196 Table 1 SV1/SV2
//!   session keys, Table 4 session key) — no public raw AES-CMAC entry
//!   point; `crypto::suite::cmac_aes` is `pub(crate)`.
//! - `derive_keys` (26) — the crate ships AN10922 key diversification
//!   (`key_diversification::diversify_ntag424`), not the boltcard
//!   deterministic derivation (tags `2D003F75`..`2D003F7B`) the vectors
//!   pin.
//! - `sv2_build` (2) — SV2 construction is internal to the verifier; the
//!   `sun_mac`/`sdm_full` vectors exercise the same SV2 bytes
//!   cryptographically (a wrong SV2 cannot produce the pinned MAC).
//! - negative `sdm_full` vectors (3) run through the same
//!   `sdm_full_vectors` test, asserting that verification REJECTS.

use ntag424::sdm::Verifier;
use ntag424::types::KeyNumber;
use ntag424::types::file_settings::{
    CryptoMode, CtrRetAccess, EncryptedContent, FileRead, MacWindow, Offset, PiccData, PlainMirror,
    ReadCtrFeatures, ReadCtrMirror, Sdm,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("vectors.json");
const VECTORS_LOCK: &str = include_str!("LOCK");
const VECTORS_SHA256: &str = "522cab963c3f7db1ab9249c0d4e207b43abc0b4061323fd5c55755959a4ff65f";

fn vectors() -> Vec<Value> {
    let parsed: Value = serde_json::from_str(VECTORS_JSON).expect("vendored vectors.json parses");
    parsed["vectors"].as_array().expect("vectors array").clone()
}

#[test]
fn vendored_vectors_are_reference_locked() {
    use sha2::{Digest, Sha256};
    let digest = hex_upper(&Sha256::digest(VECTORS_JSON.as_bytes()));
    assert_eq!(
        digest, VECTORS_SHA256,
        "vendored vectors.json drifted from the canonical generation (see tests/LOCK)"
    );
    assert!(
        VECTORS_LOCK.contains(&format!("vectors.json sha256: {VECTORS_SHA256}")),
        "tests/LOCK does not pin the vendored sha256"
    );
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length: {s}"
    );
    let bytes = s.as_bytes();
    (0..bytes.len() / 2)
        .map(|i| {
            let hi = (bytes[2 * i] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("hex digit") as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn hex_str(v: &Value, field: &str, id: &str) -> String {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("vector {id}: missing field {field}"))
        .to_ascii_lowercase()
}

fn ascii_hex(bytes: &[u8]) -> String {
    // NDEF SDM placeholders are ASCII hex; the crate's decoder accepts
    // lower and upper case.
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ctr_le_u32(counter_bytes: &[u8]) -> u32 {
    // The crate exposes the read counter as a little-endian u32 built from
    // the three verbatim PICCData bytes.
    u32::from_le_bytes([counter_bytes[0], counter_bytes[1], counter_bytes[2], 0])
}

const RCTR_FEATURES: ReadCtrFeatures = ReadCtrFeatures {
    limit: None,
    ret_access: CtrRetAccess::NoAccess,
};

/// SDM settings for a synthetic NDEF buffer laid out as:
/// `PICCENCData (32 ASCII chars) || SDMMAC (16 ASCII chars)`, with an
/// empty MAC input window (`input == mac`), K1 as `SDMMetaRead` and K2 as
/// `SDMFileRead`.
fn encrypted_layout_verifier() -> Verifier {
    let sdm = Sdm::try_new(
        PiccData::Encrypted {
            key: KeyNumber::Key1,
            offset: Offset::new(0).unwrap(),
            content: EncryptedContent::Both(RCTR_FEATURES),
        },
        Some(FileRead::MacOnly {
            key: KeyNumber::Key2,
            window: MacWindow {
                input: Offset::new(32).unwrap(),
                mac: Offset::new(32).unwrap(),
            },
        }),
        None,
        CryptoMode::Aes,
    )
    .unwrap();
    Verifier::try_new(&sdm, CryptoMode::Aes).unwrap()
}

/// SDM settings for a synthetic NDEF buffer laid out as:
/// `UID (14 ASCII chars) || SDMReadCtr (6 ASCII chars) || SDMMAC (16
/// ASCII chars)`, with an empty MAC input window.
fn plain_layout_verifier() -> Verifier {
    let sdm = Sdm::try_new(
        PiccData::Plain(PlainMirror::Both {
            uid: Offset::new(0).unwrap(),
            read_ctr: ReadCtrMirror {
                offset: Offset::new(14).unwrap(),
                features: RCTR_FEATURES,
            },
        }),
        Some(FileRead::MacOnly {
            key: KeyNumber::Key2,
            window: MacWindow {
                input: Offset::new(20).unwrap(),
                mac: Offset::new(20).unwrap(),
            },
        }),
        None,
        CryptoMode::Aes,
    )
    .unwrap();
    Verifier::try_new(&sdm, CryptoMode::Aes).unwrap()
}

#[test]
fn suite_accounting() {
    let all = vectors();
    assert_eq!(
        all.len(),
        46,
        "vendored vectors.json changed size - re-vendor from the canonical repo"
    );
    // Expressible via public API: 13 vectors (1 picc_decrypt, 1 sun_mac,
    // 11 sdm_full incl. 3 negative). Skipped: 33 (5 aes_cmac, 26
    // derive_keys, 2 sv2_build), each skip-reason documented in the module
    // docs above.
    let skipped = ["aes_cmac", "derive_keys", "sv2_build"];
    let skipped_count = all
        .iter()
        .filter(|v| skipped.contains(&v["input"]["op"].as_str().unwrap()))
        .count();
    assert_eq!(skipped_count, 33);
    let negative_count = all
        .iter()
        .filter(|v| v["negative"].as_bool() == Some(true))
        .count();
    assert_eq!(negative_count, 3);
}

#[test]
fn an12196_picc_decrypt() {
    let verifier = encrypted_layout_verifier();
    for v in vectors() {
        if v["input"]["op"].as_str() != Some("picc_decrypt") {
            continue;
        }
        let id = v["id"].as_str().unwrap();
        let key: [u8; 16] = unhex(&hex_str(&v["input"], "key", id)).try_into().unwrap();
        let ndef = ascii_hex(&unhex(&hex_str(&v["input"], "picc_enc_data", id))) + &"0".repeat(16);

        let (uid, ctr) = verifier
            .decrypt_picc_data(&key, ndef.as_bytes())
            .unwrap_or_else(|e| panic!("vector {id}: decrypt failed: {e}"));
        assert_eq!(
            uid.unwrap_or_default(),
            *unhex(&hex_str(&v["expected"], "uid", id)).as_slice(),
            "vector {id}: uid"
        );
        let expected_ctr_bytes = unhex(&hex_str(&v["expected"], "counter_bytes", id));
        assert_eq!(
            ctr.unwrap_or_default(),
            ctr_le_u32(&expected_ctr_bytes),
            "vector {id}: read counter (little-endian interpretation of {})",
            hex_str(&v["expected"], "counter_bytes", id)
        );
    }
}

#[test]
fn an12196_sun_mac() {
    let verifier = plain_layout_verifier();
    for v in vectors() {
        if v["input"]["op"].as_str() != Some("sun_mac") {
            continue;
        }
        let id = v["id"].as_str().unwrap();
        let key: [u8; 16] = unhex(&hex_str(&v["input"], "key", id)).try_into().unwrap();
        let uid = unhex(&hex_str(&v["input"], "uid", id));
        let counter_bytes = unhex(&hex_str(&v["input"], "counter_bytes", id));
        // Known-answer check: the placeholder carries the vector's
        // expected MACt; verify recomputes CMAC(K2-derived session key,
        // empty window) and must match it byte-for-byte.
        let mac = hex_str(&v["expected"], "cmac_truncated", id);
        // Plain mirrors carry the read counter MSB-first; counter_bytes is
        // the verbatim PICCData order (LSB-first), so reverse for the ASCII
        // placeholder.
        let ctr_msb_first: Vec<u8> = counter_bytes.iter().rev().copied().collect();
        let ndef = ascii_hex(&uid) + &ascii_hex(&ctr_msb_first) + &mac;

        let verified = verifier
            .verify(ndef.as_bytes(), &key)
            .unwrap_or_else(|e| panic!("vector {id}: MAC verification failed: {e}"));
        assert_eq!(
            verified.uid.unwrap_or_default(),
            *uid.as_slice(),
            "vector {id}: uid"
        );
        assert_eq!(
            verified.read_ctr.unwrap_or_default(),
            ctr_le_u32(&counter_bytes),
            "vector {id}: read counter"
        );
    }
}

#[test]
fn sdm_full_vectors() {
    let verifier = encrypted_layout_verifier();
    for v in vectors() {
        if v["input"]["op"].as_str() != Some("sdm_full") {
            continue;
        }
        let id = v["id"].as_str().unwrap();
        let k1: [u8; 16] = unhex(&hex_str(&v["input"], "k1", id)).try_into().unwrap();
        let k2: [u8; 16] = unhex(&hex_str(&v["input"], "k2", id)).try_into().unwrap();
        let ndef =
            ascii_hex(&unhex(&hex_str(&v["input"], "p", id))) + &hex_str(&v["input"], "c", id);

        // Full chain: PICC decrypt with K1, SV2 build, session-key
        // derivation from K2, CMAC over the empty MAC window, truncation
        // compared against the c= placeholder.
        let verified = verifier.verify_with_meta_key(ndef.as_bytes(), &k2, &k1);

        if v["negative"].as_bool() == Some(true) {
            // Reject vectors: the chain must refuse the p/c pair — either
            // the PICCDataTag parse fails (e.g. 0xC6 → uid length 6) or
            // the SUN MAC does not match.
            assert!(
                verified.is_err(),
                "negative vector {id}: verification must reject"
            );
            continue;
        }

        let verified = verified.unwrap_or_else(|e| panic!("vector {id}: verification failed: {e}"));
        assert_eq!(
            verified.uid.unwrap_or_default(),
            *unhex(&hex_str(&v["expected"], "uid", id)).as_slice(),
            "vector {id}: uid"
        );
        assert_eq!(
            verified.read_ctr.unwrap_or_default(),
            ctr_le_u32(&unhex(&hex_str(&v["expected"], "counter_bytes", id))),
            "vector {id}: read counter"
        );

        // decrypt_picc_data must agree on UID/counter bytes.
        let (uid, ctr) = verifier
            .decrypt_picc_data(&k1, ndef.as_bytes())
            .unwrap_or_else(|e| panic!("vector {id}: decrypt failed: {e}"));
        assert_eq!(
            uid.unwrap_or_default(),
            *unhex(&hex_str(&v["expected"], "uid", id)).as_slice(),
            "vector {id}: decrypt uid"
        );
        assert_eq!(
            ctr.unwrap_or_default(),
            ctr_le_u32(&unhex(&hex_str(&v["expected"], "counter_bytes", id))),
            "vector {id}: decrypt read counter"
        );
    }
}
