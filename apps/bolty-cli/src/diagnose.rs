//! `diagnose` command: non-destructive card state classifier.
//!
//! Reads UID, version, file settings, and NDEF content (all unauthenticated),
//! then optionally attempts a single factory K0 authentication — only when
//! the card appears blank. Classifies the card into one of:
//!
//! - `BLANK` — factory keys, no SDM, empty NDEF
//! - `PROVISIONED` — SDM active, NDEF has content, PICC verifies
//! - `HALF-WIPED` — mixed state (factory keys with residual data, or SDM without NDEF)
//! - `AUTH_DELAY` — card is rate-limiting authentication attempts
//! - `INCONSISTENT` — does not match any known pattern

use anyhow::Context;
use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc as picc_crypto;
use bolty_core::provenance::KeyProvenance;
use bolty_core::uid::CardUid;
use bolty_ntag::{CryptoMode, File, KeyNumber, Session, Transport, Verifier};

use crate::common::{
    gen_rnd_a, is_auth_delay, is_sdm_functionally_active, parse_ndef_uri, uid_to_fixed,
};

/// Standard Bolt Card key version.
const DEFAULT_VERSION: u32 = 1;

fn classify_card_state(
    auth_delay: bool,
    has_sdm: bool,
    has_ndef_content: bool,
    factory_auth_ok: bool,
) -> &'static str {
    if auth_delay {
        "AUTH_DELAY"
    } else if !has_sdm && !has_ndef_content {
        if factory_auth_ok {
            "BLANK"
        } else {
            "INCONSISTENT"
        }
    } else if has_sdm && has_ndef_content {
        "PROVISIONED"
    } else {
        "HALF-WIPED"
    }
}

/// Classify the provenance of the key currently on K0.
///
/// Priority: FactoryDefault > DerivedIssuer > StaticTestKey > UnknownExternal.
/// Factory wins because a working factory K0 means the card is genuinely blank.
/// DerivedIssuer (via SDM MAC verification) wins over StaticTestKey because
/// cryptographic proof outranks a single static-key auth success.
fn classify_key_provenance(
    factory_auth_ok: bool,
    picc_ok: bool,
    static_test_auth_ok: bool,
) -> KeyProvenance {
    if factory_auth_ok {
        KeyProvenance::FactoryDefault
    } else if picc_ok {
        KeyProvenance::DerivedIssuer {
            version: DEFAULT_VERSION as u8,
        }
    } else if static_test_auth_ok {
        KeyProvenance::StaticTestKey
    } else {
        KeyProvenance::UnknownExternal
    }
}

/// Build the flat JSON output string for the diagnose command.
///
/// Extracted from `cmd_diagnose` so tests can assert on the JSON shape
/// without capturing stdout (no stdout-capture mechanism in this crate).
fn build_diagnose_json(
    uid_hex: &str,
    state: &str,
    has_sdm: bool,
    mac_valid: bool,
    provenance: &KeyProvenance,
) -> String {
    let prov_name = provenance.as_json_name();
    let prov_version_field = match provenance.json_version() {
        Some(v) => format!(",\"key_provenance_version\":{v}"),
        None => String::new(),
    };
    format!(
        r#"{{"ok":true,"uid":"{uid_hex}","state":"{state}","sdm_active":{has_sdm},"mac_valid":{mac_valid},"key_provenance":"{prov_name}"{prov_version_field}}}"#
    )
}

pub async fn cmd_diagnose<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    json: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();
    println!("=== DIAGNOSE ===\n");

    // 1. UID
    let uid_fixed = {
        let uid = session
            .get_selected_uid(transport)
            .await
            .context("failed to read UID")?;
        let fixed = uid_to_fixed(&uid);
        println!("UID:            {}", crate::to_hex(fixed));
        fixed
    };

    // 2. Version
    let is_ntag424 = match session.get_version(transport).await {
        Ok(v) => {
            println!(
                "Version:        HW vendor={:02X} type={:02X} v={:02X}.{:02X} | SW vendor={:02X} type={:02X} v={:02X}.{:02X}",
                v.hw_vendor_id(),
                v.hw_type(),
                v.hw_major_version(),
                v.hw_minor_version(),
                v.sw_vendor_id(),
                v.sw_type(),
                v.sw_major_version(),
                v.sw_minor_version(),
            );
            v.hw_vendor_id() == 0x04
        }
        Err(e) => {
            println!("Version:        FAILED ({e})");
            false
        }
    };

    // 3. File settings (unauthenticated)
    let mut sdm_settings = None;
    let has_sdm = match session.get_file_settings(transport, File::Ndef).await {
        Ok(settings) => {
            let active = is_sdm_functionally_active(settings.sdm.as_ref());
            println!("SDM active:     {active}");
            println!("File settings:  {settings:?}");
            sdm_settings = settings.sdm;
            active
        }
        Err(e) => {
            println!("File settings:  FAILED ({e})");
            false
        }
    };

    // 4. NDEF content (unauthenticated)
    let mut buf = [0u8; 256];
    let (ndef_len, has_ndef_content, ndef_parsed) = match session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
    {
        Ok(len) => {
            let clamped = len.min(buf.len());
            let data = buf.get(..clamped).unwrap_or(&[]);
            let parsed = parse_ndef_uri(data);
            let has_content = parsed.is_some();
            match &parsed {
                Some(p) => println!("NDEF:           {clamped} bytes, URL={}", p.url),
                None => println!("NDEF:           {clamped} bytes, no valid URI"),
            }
            (clamped, has_content, parsed)
        }
        Err(e) => {
            println!("NDEF:           FAILED ({e})");
            (0, false, None)
        }
    };

    let picc_ok = if has_sdm {
        if let Some(ref parsed) = ndef_parsed {
            if let (Some(p_hex), Some(c_hex)) = (&parsed.picc_hex, &parsed.mac_hex) {
                println!("\nSDM params:     p={p_hex} c={c_hex}");
                let keys = BoltcardDeterministicDeriver::derive_keys(
                    issuer_key,
                    CardUid::new(uid_fixed),
                    DEFAULT_VERSION,
                );
                match picc_crypto::picc_decrypt_p(keys.k1.as_bytes(), p_hex) {
                    Some(picc) => {
                        let uid_match = picc.uid == uid_fixed;
                        let mac_ok = sdm_settings
                            .as_ref()
                            .and_then(|sdm| Verifier::try_new(sdm, CryptoMode::Aes).ok())
                            .and_then(|v| {
                                let ndef_data = buf.get(..ndef_len).unwrap_or(&[]);
                                v.verify_with_meta_key(
                                    ndef_data,
                                    keys.k2.as_bytes(),
                                    keys.k1.as_bytes(),
                                )
                                .ok()
                            })
                            .is_some();
                        println!(
                            "SDM verify:     uid_match={uid_match}, counter={}, mac={mac_ok}",
                            picc.counter
                        );
                        uid_match && mac_ok
                    }
                    None => {
                        println!("PICC decrypt:   FAILED (wrong issuer key?)");
                        false
                    }
                }
            } else {
                println!("\nSDM active but no p=/c= in NDEF URL");
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // 6. Factory K0 authentication — only if card appears blank.
    let looks_blank = !has_sdm && !has_ndef_content;
    let mut factory_auth_ok = false;
    let mut auth_delay = false;

    if looks_blank {
        println!("\nCard appears blank — trying factory K0...");
        let rnd_a = gen_rnd_a()?;
        match Session::default()
            .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
            .await
        {
            Ok(_) => {
                println!("  Factory K0:    OK");
                factory_auth_ok = true;
            }
            Err(ref e) if is_auth_delay(e) => {
                println!("  Factory K0:    AUTH_DELAY");
                auth_delay = true;
            }
            Err(e) => {
                println!("  Factory K0:    FAILED ({e})");
            }
        }
    }

    // 6b. Static test-key probe — bounded single attempt, only when the card
    // is neither factory-authable nor SDM-derivable and not in auth delay.
    // Probes the M5StickC marker key [0x11u8; 16] against K0.
    let static_test_auth_ok = if !factory_auth_ok && !picc_ok && !auth_delay {
        println!("\nCard not factory/derivable — trying M5StickC static test K0...");
        let rnd_a = gen_rnd_a()?;
        match Session::default()
            .authenticate_aes(transport, KeyNumber::Key0, &[0x11u8; 16], rnd_a)
            .await
        {
            Ok(_) => {
                println!("  Static K0:     OK (M5StickC test key)");
                true
            }
            Err(ref e) if is_auth_delay(e) => {
                println!("  Static K0:     AUTH_DELAY");
                false
            }
            Err(e) => {
                println!("  Static K0:     FAILED ({e})");
                false
            }
        }
    } else {
        false
    };

    let provenance = classify_key_provenance(factory_auth_ok, picc_ok, static_test_auth_ok);

    // 7. Classify.
    let state = classify_card_state(auth_delay, has_sdm, has_ndef_content, factory_auth_ok);

    if json {
        let uid_hex = crate::to_hex(uid_fixed);
        let mac_valid = picc_ok;
        println!(
            "{}",
            build_diagnose_json(&uid_hex, state, has_sdm, mac_valid, &provenance)
        );
    } else {
        println!("\n=== DIAGNOSIS ===");
        println!("Card state:     {state}");
        println!("Key provenance:  {}", provenance.to_audit_tag());
        match state {
            "BLANK" => {
                println!("  Factory keys, no SDM, empty NDEF.");
                println!("  Ready to burn: bolty-cli burn --issuer-key <KEY> --url <URL>");
            }
            "PROVISIONED" => {
                if picc_ok {
                    println!("  SDM active, PICC decrypts and verifies with provided issuer key.");
                } else {
                    println!("  SDM active but PICC verification failed.");
                    println!("  Card may use a different issuer key or key version.");
                }
            }
            "HALF-WIPED" => {
                println!("  Mixed state: SDM={has_sdm}, NDEF_content={has_ndef_content}.");
                if factory_auth_ok {
                    println!("  Factory K0 works — re-burn to recover.");
                } else {
                    println!("  Try `wipe` with the correct issuer key, then re-burn.");
                }
            }
            "AUTH_DELAY" => {
                println!("  Card is rate-limiting auth. Wait 5-10s and re-run diagnose.");
            }
            _ => {
                println!("  Does not match any known pattern.");
                println!(
                    "  SDM={has_sdm}, NDEF={has_ndef_content}, NDEF_len={ndef_len}, NTAG424={is_ntag424}"
                );
                if !is_ntag424 {
                    println!("  Card may not be an NTAG424.");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_blank_with_factory_auth() {
        assert_eq!(classify_card_state(false, false, false, true), "BLANK");
    }

    #[test]
    fn classify_blank_without_factory_auth() {
        assert_eq!(
            classify_card_state(false, false, false, false),
            "INCONSISTENT"
        );
    }

    #[test]
    fn classify_provisioned() {
        assert_eq!(classify_card_state(false, true, true, false), "PROVISIONED");
    }

    #[test]
    fn classify_half_wiped_sdm_only() {
        assert_eq!(classify_card_state(false, true, false, false), "HALF-WIPED");
    }

    #[test]
    fn classify_half_wiped_ndef_only() {
        assert_eq!(classify_card_state(false, false, true, false), "HALF-WIPED");
    }

    #[test]
    fn classify_auth_delay_overrides_all() {
        assert_eq!(classify_card_state(true, true, true, true), "AUTH_DELAY");
    }

    #[test]
    fn classify_auth_delay_with_blank_signals() {
        assert_eq!(classify_card_state(true, false, false, false), "AUTH_DELAY");
    }

    // ── Key provenance classification ──────────────────────────────

    #[test]
    fn classify_provenance_factory() {
        // factory_auth_ok wins over everything.
        assert_eq!(
            classify_key_provenance(true, false, false),
            KeyProvenance::FactoryDefault
        );
        assert_eq!(
            classify_key_provenance(true, true, true),
            KeyProvenance::FactoryDefault
        );
    }

    #[test]
    fn classify_provenance_derived() {
        // picc_ok (SDM MAC verified) → DerivedIssuer with default version.
        assert_eq!(
            classify_key_provenance(false, true, false),
            KeyProvenance::DerivedIssuer {
                version: DEFAULT_VERSION as u8
            }
        );
        // picc_ok wins over static_test_auth_ok.
        assert_eq!(
            classify_key_provenance(false, true, true),
            KeyProvenance::DerivedIssuer {
                version: DEFAULT_VERSION as u8
            }
        );
    }

    #[test]
    fn classify_provenance_static() {
        assert_eq!(
            classify_key_provenance(false, false, true),
            KeyProvenance::StaticTestKey
        );
    }

    #[test]
    fn classify_provenance_unknown() {
        assert_eq!(
            classify_key_provenance(false, false, false),
            KeyProvenance::UnknownExternal
        );
    }

    #[tokio::test]
    async fn json_includes_provenance() {
        // Integration: cmd_diagnose must complete successfully against a
        // factory-default mock card. The mock has factory (all-zero) keys,
        // empty NDEF, and no SDM — so diagnose yields factory_auth_ok=true
        // and provenance=FactoryDefault.
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        cmd_diagnose(&mut transport, &issuer_key, true)
            .await
            .expect("diagnose against factory-default mock must succeed");

        // Unit: the JSON builder must include the provenance field and, for
        // DerivedIssuer, the version field. Stdout is not captured (no
        // capture mechanism in this crate); instead we assert directly on
        // the pure builder helper.
        let factory_json = build_diagnose_json(
            "041065FA967380",
            "BLANK",
            false,
            false,
            &KeyProvenance::FactoryDefault,
        );
        assert!(
            factory_json.contains("\"key_provenance\":\"FactoryDefault\""),
            "factory JSON must include key_provenance, got: {factory_json}"
        );

        let derived_json = build_diagnose_json(
            "041065FA967380",
            "PROVISIONED",
            true,
            true,
            &KeyProvenance::DerivedIssuer {
                version: DEFAULT_VERSION as u8,
            },
        );
        assert!(
            derived_json.contains("\"key_provenance\":\"DerivedIssuer\""),
            "derived JSON must include key_provenance, got: {derived_json}"
        );
        assert!(
            derived_json.contains("\"key_provenance_version\":1"),
            "derived JSON must include key_provenance_version, got: {derived_json}"
        );
    }
}

/// SECURITY regression suite for the diagnose classifiers (issue #41).
///
/// Pins the two pure classifier functions that decide a card's trust label and
/// lifecycle state. A regression here would mislabel cards — e.g. calling an
/// auth-delayed card "BLANK" (leading to brute-force that bricks the key) or
/// labelling a factory card as "UnknownExternal" (hiding a genuine blank). The
/// integration test in `tests/security/` covers the `KeyProvenance` *type*
/// properties; this module covers the *decision logic* that maps auth results
/// to those labels.
#[cfg(test)]
mod security_tests {
    use super::{
        DEFAULT_VERSION, build_diagnose_json, classify_card_state, classify_key_provenance,
    };
    use bolty_core::assessment::CardLifecycleState;
    use bolty_core::provenance::KeyProvenance;

    const V1: u8 = DEFAULT_VERSION as u8;

    // ── classify_key_provenance: trust priority ─────────────────────────

    // SECURITY invariant: factory authentication must dominate every other
    // signal. A card that authenticates with the factory (all-zero) key IS
    // blank regardless of what else probes return — labelling it otherwise
    // could trigger an unnecessary re-burn that wears the key-write limit.
    #[test]
    fn factory_auth_dominates_all_other_signals() {
        assert_eq!(
            classify_key_provenance(true, true, true),
            KeyProvenance::FactoryDefault
        );
        assert_eq!(
            classify_key_provenance(true, false, false),
            KeyProvenance::FactoryDefault
        );
    }

    // SECURITY invariant: SDM MAC verification (picc_ok) outranks a static
    // test-key auth. Cryptographic proof of the issuer-key derivation must
    // never be downgraded to "StaticTestKey" just because the static probe
    // also succeeded.
    #[test]
    fn derived_issuer_outranks_static_test_key() {
        assert_eq!(
            classify_key_provenance(false, true, true),
            KeyProvenance::DerivedIssuer { version: V1 }
        );
    }

    // SECURITY invariant: a static test-key success alone labels the card as
    // StaticTestKey — a recognised insecure tier, NOT UnknownExternal. This
    // flags cards burned by the M5StickC firmware distinctly so they are not
    // mistaken for foreign/unknown cards.
    #[test]
    fn static_test_key_alone_is_labelled_static() {
        assert_eq!(
            classify_key_provenance(false, false, true),
            KeyProvenance::StaticTestKey
        );
    }

    // SECURITY invariant: when no probe succeeds, the label must be the
    // fail-closed UnknownExternal — never a trusted variant. This is the
    // default-deny posture for unrecognised cards.
    #[test]
    fn no_probe_success_labels_unknown_external() {
        assert_eq!(
            classify_key_provenance(false, false, false),
            KeyProvenance::UnknownExternal
        );
    }

    // SECURITY invariant: picc_ok without factory auth must yield DerivedIssuer
    // carrying the default version, so the audit log records which burn
    // generation verified successfully.
    #[test]
    fn picc_ok_yields_derived_issuer_with_version() {
        let p = classify_key_provenance(false, true, false);
        assert_eq!(p, KeyProvenance::DerivedIssuer { version: V1 });
        assert_eq!(p.json_version(), Some(V1));
    }

    // SECURITY invariant: the priority order is total — there is no input
    // combination that leaves the function without a label. Enumerate the
    // entire 3-bit input space and assert each maps to exactly one variant.
    #[test]
    fn provenance_classifier_is_total_over_input_space() {
        for &factory in &[false, true] {
            for &picc in &[false, true] {
                for &statik in &[false, true] {
                    let _ = classify_key_provenance(factory, picc, statik);
                    // No panic / no fall-through: the function always returns.
                }
            }
        }
        // Spot-check the four boundary labels one more time.
        assert_eq!(
            classify_key_provenance(true, false, false),
            KeyProvenance::FactoryDefault
        );
        assert_eq!(
            classify_key_provenance(false, true, false),
            KeyProvenance::DerivedIssuer { version: V1 }
        );
        assert_eq!(
            classify_key_provenance(false, false, true),
            KeyProvenance::StaticTestKey
        );
        assert_eq!(
            classify_key_provenance(false, false, false),
            KeyProvenance::UnknownExternal
        );
    }

    // ── classify_card_state: lifecycle guards ───────────────────────────

    // SECURITY invariant: AUTH_DELAY must override every other signal. Treating
    // a rate-limited card as BLANK/PROVISIONED would trigger more auth attempts
    // and push TotFailCtr toward the 1000-failure permanent lock.
    #[test]
    fn auth_delay_overrides_all_state_signals() {
        assert_eq!(classify_card_state(true, true, true, true), "AUTH_DELAY");
        assert_eq!(classify_card_state(true, false, false, false), "AUTH_DELAY");
    }

    // SECURITY invariant: a card with neither SDM nor NDEF content that ALSO
    // fails factory auth is INCONSISTENT, not BLANK. Calling it BLANK would
    // invite a burn against a card whose K0 is unknown — potentially writing
    // over a third party's keys.
    #[test]
    fn blank_signals_without_factory_auth_is_inconsistent() {
        assert_eq!(
            classify_card_state(false, false, false, false),
            "INCONSISTENT"
        );
    }

    // SECURITY invariant: a genuinely blank card (no SDM, no NDEF, factory auth
    // OK) is the only state safe to burn without a re-auth probe. This must
    // stay labelled BLANK.
    #[test]
    fn blank_signals_with_factory_auth_is_blank() {
        assert_eq!(classify_card_state(false, false, false, true), "BLANK");
    }

    // SECURITY invariant: SDM + NDEF content is PROVISIONED. This is the only
    // state where deriving keys and verifying a tap is meaningful.
    #[test]
    fn sdm_plus_ndef_content_is_provisioned() {
        assert_eq!(classify_card_state(false, true, true, false), "PROVISIONED");
    }

    // SECURITY invariant: a mixed state (SDM without NDEF, or NDEF without
    // SDM) is HALF-WIPED — never PROVISIONED and never BLANK. Treating it as
    // either would hide a half-finished wipe and corrupt the lifecycle model.
    #[test]
    fn mixed_state_is_half_wiped() {
        assert_eq!(classify_card_state(false, true, false, false), "HALF-WIPED");
        assert_eq!(classify_card_state(false, false, true, false), "HALF-WIPED");
    }

    // SECURITY invariant: factory auth success alone (without checking the SDM
    // / NDEF signals) never flips a HALF-WIPED card to BLANK. The presence of
    // residual data must dominate, so a half-wiped card is not silently
    // treated as fresh.
    #[test]
    fn half_wiped_with_factory_auth_still_half_wiped() {
        assert_eq!(classify_card_state(false, true, false, true), "HALF-WIPED");
        assert_eq!(classify_card_state(false, false, true, true), "HALF-WIPED");
    }

    // SECURITY invariant (issue #40): the new typed enum
    // `CardLifecycleState::from_signals` must reproduce
    // `classify_card_state` exactly across the full 16-input truth table.
    // Any drift would split the lifecycle model from the string classifier
    // and silently change burn/wipe/diagnose gating. This test enumerates
    // every (auth_delay, has_sdm, has_ndef_content, factory_auth_ok)
    // combination and asserts label equality.
    #[test]
    fn from_signals_matches_classify_card_state_exhaustive() {
        for &auth_delay in &[false, true] {
            for &has_sdm in &[false, true] {
                for &has_ndef in &[false, true] {
                    for &factory_auth in &[false, true] {
                        let expected =
                            classify_card_state(auth_delay, has_sdm, has_ndef, factory_auth);
                        let got = CardLifecycleState::from_signals(
                            auth_delay,
                            has_sdm,
                            has_ndef,
                            factory_auth,
                        )
                        .as_str();
                        assert_eq!(
                            got, expected,
                            "divergence at (auth_delay={auth_delay}, has_sdm={has_sdm}, \
                             has_ndef={has_ndef}, factory_auth={factory_auth}): \
                             enum said {got:?}, classifier said {expected:?}"
                        );
                    }
                }
            }
        }
    }

    // ── build_diagnose_json: output-shape integrity ─────────────────────

    // SECURITY invariant: the JSON output must always carry a key_provenance
    // field, so a downstream consumer never has to guess the trust tier. The
    // field is the machine-readable security label.
    #[test]
    fn json_always_carries_key_provenance_field() {
        for prov in [
            KeyProvenance::FactoryDefault,
            KeyProvenance::DerivedIssuer { version: V1 },
            KeyProvenance::StaticTestKey,
            KeyProvenance::UnknownExternal,
        ] {
            let json = build_diagnose_json("041065FA967380", "BLANK", false, false, &prov);
            assert!(
                json.contains("\"key_provenance\":"),
                "JSON must always include key_provenance for {prov:?}: {json}"
            );
        }
    }

    // SECURITY invariant: DerivedIssuer JSON must carry the version field so an
    // auditor can distinguish burn generations. The other variants must omit
    // it (no spurious null), keeping the schema strict.
    #[test]
    fn json_version_field_present_only_for_derived() {
        let derived = build_diagnose_json(
            "041065FA967380",
            "PROVISIONED",
            true,
            true,
            &KeyProvenance::DerivedIssuer { version: V1 },
        );
        assert!(derived.contains("\"key_provenance_version\":1"));

        let factory = build_diagnose_json(
            "041065FA967380",
            "BLANK",
            false,
            false,
            &KeyProvenance::FactoryDefault,
        );
        assert!(
            !factory.contains("key_provenance_version"),
            "non-derived JSON must omit key_provenance_version: {factory}"
        );
    }
}
