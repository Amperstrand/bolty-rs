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
use bolty_core::uid::CardUid;
use ntag424::{
    File, KeyNumber, Session, Transport, sdm::Verifier, types::file_settings::CryptoMode,
};

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

pub async fn cmd_diagnose<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
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

    // 7. Classify.
    println!("\n=== DIAGNOSIS ===");

    let state = classify_card_state(auth_delay, has_sdm, has_ndef_content, factory_auth_ok);

    println!("Card state:     {state}");

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
}
