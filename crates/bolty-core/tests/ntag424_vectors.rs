// SPDX-FileCopyrightText: 2026 Amperstrand
//
// SPDX-License-Identifier:: Apache-2.0

//! Cross-language NTAG424 conformance suite from
//! <https://github.com/Amperstrand/ntag424-vectors> (vendored at
//! `tests/fixtures/ntag424-vectors/vectors.json`, reference-locked by the
//! sibling `LOCK` file — `make vectors-check` verifies the hash).
//!
//! Runs every vector `bolty-core`'s public API can express:
//!
//! - `aes_cmac`      — `crypto::aes_cmac`
//! - `sv2_build`     — `picc::sdm_build_sv2` / `sdm_build_sv2_no_uid`
//! - `picc_decrypt`  — `picc::picc_decrypt_p` (UID + counter mirrors)
//! - `sun_mac`       — `crypto::aes_cmac` over the `picc::sdm_build_sv2`
//!                     chain (ks = CMAC(K2, SV2); ct = odd bytes of
//!                     CMAC(ks, empty)) — same shape `picc_verify_c` checks
//! - `sdm_full`      — `picc::picc_parse_url` (decrypt + SUN verify);
//!                     negative vectors MUST be rejected
//! - `derive_keys`   — `derivation::BoltcardDeterministicDeriver::derive_keys`
//!
//! Nothing is skipped: every op in the suite is expressible here.

use bolty_core::crypto::aes_cmac;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc::{picc_decrypt_p, picc_parse_url, sdm_build_sv2, sdm_build_sv2_no_uid};
use bolty_core::uid::CardUid;
use bolty_core::util::decode_hex;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../tests/fixtures/ntag424-vectors/vectors.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

fn field<'a>(v: &'a Value, path: &str) -> &'a str {
    v[path]
        .as_str()
        .unwrap_or_else(|| panic!("missing field {path}"))
}

fn ctr_from_bytes(bytes: &[u8]) -> u32 {
    u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16)
}

fn truncate_odd(mac: &[u8; 16]) -> [u8; 8] {
    core::array::from_fn(|i| mac[i * 2 + 1])
}

#[test]
fn ntag424_vectors_suite() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors.json parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(
        vectors.len(),
        46,
        "suite size changed — re-vendor deliberately"
    );

    let (mut ran, mut negatives) = (0usize, 0usize);
    for v in vectors {
        let id = field(v, "id");
        let input = &v["input"];
        let expected = &v["expected"];
        let op = field(input, "op");
        let negative = v["negative"].as_bool().unwrap_or(false);
        ran += 1;

        match op {
            "aes_cmac" => {
                let key: [u8; 16] = decode_hex(field(input, "key")).unwrap();
                let msg = hex_bytes(field(input, "message"));
                assert_eq!(hex(&aes_cmac(&key, &msg)), field(expected, "cmac"), "{id}");
            }
            "sv2_build" => {
                let ctr_bytes: [u8; 3] = decode_hex(field(input, "counter_bytes")).unwrap();
                let sv2 = match input["uid"].as_str() {
                    Some(uid_hex) => {
                        let uid: [u8; 7] = decode_hex(uid_hex).unwrap();
                        sdm_build_sv2(&uid, ctr_from_bytes(&ctr_bytes))
                    }
                    None => sdm_build_sv2_no_uid(ctr_from_bytes(&ctr_bytes)),
                };
                assert_eq!(hex(&sv2), field(expected, "sv2"), "{id}");
            }
            "picc_decrypt" => {
                let key: [u8; 16] = decode_hex(field(input, "key")).unwrap();
                let picc = picc_decrypt_p(&key, field(input, "picc_enc_data"))
                    .unwrap_or_else(|| panic!("{id}: decrypt failed"));
                let uid = picc.uid.expect("{id}: uid missing");
                assert_eq!(hex(&uid), field(expected, "uid"), "{id}");
                assert_eq!(
                    hex(&[
                        picc.counter as u8,
                        (picc.counter >> 8) as u8,
                        (picc.counter >> 16) as u8
                    ]),
                    field(expected, "counter_bytes"),
                    "{id}"
                );
            }
            "sun_mac" => {
                let k2: [u8; 16] = decode_hex(field(input, "key")).unwrap();
                let uid: [u8; 7] = decode_hex(field(input, "uid")).unwrap();
                let ctr_bytes: [u8; 3] = decode_hex(field(input, "counter_bytes")).unwrap();
                let ks = aes_cmac(&k2, &sdm_build_sv2(&uid, ctr_from_bytes(&ctr_bytes)));
                let ct = truncate_odd(&aes_cmac(&ks, &[]));
                assert_eq!(hex(&ct), field(expected, "cmac_truncated"), "{id}");
            }
            "sdm_full" => {
                let k1: [u8; 16] = decode_hex(field(input, "k1")).unwrap();
                let k2: [u8; 16] = decode_hex(field(input, "k2")).unwrap();
                let url = format!(
                    "https://vectors.example/?p={}&c={}",
                    field(input, "p"),
                    field(input, "c")
                );
                let verdict = picc_parse_url(&k1, &k2, &url);
                if negative {
                    negatives += 1;
                    assert!(!verdict.valid, "{id}: negative vector must be rejected");
                } else {
                    assert!(verdict.valid, "{id}: positive vector must verify");
                    let uid = verdict.uid.expect("{id}: uid missing");
                    assert_eq!(hex(&uid), field(expected, "uid"), "{id}");
                    assert_eq!(
                        hex(&[
                            verdict.counter as u8,
                            (verdict.counter >> 8) as u8,
                            (verdict.counter >> 16) as u8
                        ]),
                        field(expected, "counter_bytes"),
                        "{id}"
                    );
                }
            }
            "derive_keys" => {
                let issuer: [u8; 16] = decode_hex(field(input, "issuer_key")).unwrap();
                let uid = CardUid::from_hex(field(input, "uid")).unwrap();
                let version = input["version"].as_u64().unwrap() as u32;
                let set = BoltcardDeterministicDeriver::derive_keys(&issuer, uid, version);
                for (name, actual) in [
                    ("card_key", set.card_key.as_bytes()),
                    ("k0", set.k0.as_bytes()),
                    ("k1", set.k1.as_bytes()),
                    ("k2", set.k2.as_bytes()),
                    ("k3", set.k3.as_bytes()),
                    ("k4", set.k4.as_bytes()),
                    ("card_id", &set.card_id),
                ] {
                    if let Some(want) = expected[name].as_str() {
                        assert_eq!(hex(actual), want, "{id}: {name}");
                    }
                }
            }
            other => panic!("unknown op {other} in vector {id} — update this harness"),
        }
    }

    assert_eq!(negatives, 3, "expected the 3 negative sdm_full vectors");
    eprintln!("ntag424-vectors: {ran} vectors ran, {negatives} rejected-as-negative, 0 skipped");
}
