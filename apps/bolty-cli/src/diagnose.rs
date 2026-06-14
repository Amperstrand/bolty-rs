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
use ntag424::{File, KeyNumber, Session, Transport};

use crate::common::{gen_rnd_a, is_auth_delay, uid_to_fixed};

/// Standard Bolt Card key version.
const DEFAULT_VERSION: u32 = 1;

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
    let has_sdm = match session.get_file_settings(transport, File::Ndef).await {
        Ok(settings) => {
            let active = settings.sdm.is_some();
            println!("SDM active:     {active}");
            println!("File settings:  {settings:?}");
            active
        }
        Err(e) => {
            println!("File settings:  FAILED ({e})");
            false
        }
    };

    // 4. NDEF content (unauthenticated)
    let mut buf = [0u8; 256];
    let (ndef_len, has_ndef_content, ndef_str) = match session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
    {
        Ok(len) => {
            let clamped = len.min(buf.len());
            let slice = buf.get(..clamped).unwrap_or(&[]);
            // SAFETY: clamped >= 2 check guards buf[0] and buf[1].
            #[allow(clippy::indexing_slicing)]
            let has_content = clamped >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);
            let s = String::from_utf8_lossy(slice).into_owned();
            println!("NDEF:           {clamped} bytes, content={has_content}");
            if has_content {
                println!("NDEF (text):    {s}");
            }
            (clamped, has_content, s)
        }
        Err(e) => {
            println!("NDEF:           FAILED ({e})");
            (0, false, String::new())
        }
    };

    // 5. PICC verification (local crypto only — no APDUs).
    let picc_ok = if has_sdm {
        if let Some((p_hex, c_hex)) = picc_crypto::extract_p_and_c(&ndef_str) {
            println!("\nSDM params:     p={p_hex} c={c_hex}");
            let keys = BoltcardDeterministicDeriver::derive_keys(
                issuer_key,
                CardUid::new(uid_fixed),
                DEFAULT_VERSION,
            );
            match picc_crypto::picc_decrypt_p(keys.k1.as_bytes(), p_hex) {
                Some(picc) => {
                    let uid_match = picc.uid == uid_fixed;
                    let cmac_ok = picc_crypto::picc_verify_c(keys.k2.as_bytes(), &picc, c_hex);
                    println!(
                        "PICC decrypt:   OK (uid_match={uid_match}, counter={}, cmac={cmac_ok})",
                        picc.counter
                    );
                    uid_match && cmac_ok
                }
                None => {
                    println!("PICC decrypt:   FAILED (wrong issuer key?)");
                    false
                }
            }
        } else {
            println!("\nSDM active but no p=/c= in NDEF (SDM may not have populated yet).");
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

    let state = if auth_delay {
        "AUTH_DELAY"
    } else if looks_blank {
        if factory_auth_ok {
            "BLANK"
        } else {
            "INCONSISTENT"
        }
    } else if has_sdm && has_ndef_content {
        "PROVISIONED"
    } else if has_sdm || has_ndef_content {
        "HALF-WIPED"
    } else {
        "INCONSISTENT"
    };

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
