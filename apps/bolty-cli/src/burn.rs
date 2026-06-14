use anyhow::Context;
use bolty_core::constants::{FACTORY_KEY, KEY_VERSION_BLANK};
use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use ntag424::{
    AuthenticatedSession, File, KeyNumber, NonMasterKeyNumber, Session, SessionError, Uid,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::file_settings::{CryptoMode, PiccData, Sdm},
};
use std::time::Duration;

use crate::transport::PcscTransport;

fn boltcard_sdm_opts() -> SdmUrlOptions {
    SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..SdmUrlOptions::new()
    }
}

fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

fn is_auth_delay<T: std::error::Error + std::fmt::Debug>(err: &SessionError<T>) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(ntag424::types::ResponseStatus::AuthenticationDelay)
    )
}

fn gen_rnd_a() -> anyhow::Result<[u8; 16]> {
    let mut rnd_a = [0u8; 16];
    getrandom::fill(&mut rnd_a).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    Ok(rnd_a)
}

pub async fn cmd_uid(transport: &mut PcscTransport) -> anyhow::Result<[u8; 7]> {
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("UID: {}", crate::to_hex(uid_fixed));
    Ok(uid_fixed)
}

pub async fn cmd_inspect(transport: &mut PcscTransport) -> anyhow::Result<()> {
    let mut session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("UID: {}", crate::to_hex(uid.as_ref()));

    match session.get_version(transport).await {
        Ok(v) => {
            println!(
                "Version: HW vendor={:02X} type={:02X} ver={:02X}.{:02X} | SW vendor={:02X} type={:02X} ver={:02X}.{:02X} | Batch={} CW{} {}",
                v.hw_vendor_id(),
                v.hw_type(),
                v.hw_major_version(),
                v.hw_minor_version(),
                v.sw_vendor_id(),
                v.sw_type(),
                v.sw_major_version(),
                v.sw_minor_version(),
                v.batch_number(),
                v.calendar_week_of_production(),
                v.calendar_year_of_production(),
            );
        }
        Err(e) => println!("Version: (unreadable: {e})"),
    }

    match session.get_file_settings(transport, File::Ndef).await {
        Ok(settings) => {
            println!("NDEF file settings: {settings:?}");
        }
        Err(e) => println!("NDEF file settings: (unreadable: {e})"),
    }

    let mut buf = [0u8; 256];
    match session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
    {
        Ok(len) => {
            println!("NDEF content ({} bytes): {}", len, crate::to_hex(&buf[..len]));
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                println!("NDEF (text): {s}");
            }
        }
        Err(e) => println!("NDEF content: (unreadable: {e})"),
    }

    Ok(())
}

pub async fn cmd_burn(
    transport: &mut PcscTransport,
    issuer_key: &[u8; 16],
    url: &str,
    version: u8,
) -> anyhow::Result<()> {
    let plan = sdm_url_config(url, CryptoMode::Aes, boltcard_sdm_opts())
        .map_err(|e| anyhow::anyhow!("SDM URL config error: {e}"))?;

    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    let keys = BoltcardDeterministicDeriver::derive_keys(issuer_key, &uid_fixed, version as u32);
    print_derived_keys(&keys, version);

    // --- Authenticate: factory K0 for fresh cards, derived K0 for re-burns ---
    println!("[1/7] Authenticating...");
    let rnd_a = gen_rnd_a()?;
    let (session, old_keys_are_factory) = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        Ok(s) => {
            println!("  Authenticated with factory K0");
            (s, true)
        }
        Err(_) => {
            // Factory K0 failed — card may have derived keys from a previous burn
            println!("  Factory K0 failed, trying derived K0...");
            let rnd_a = gen_rnd_a()?;
            match Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
                .await
            {
                Ok(s) => {
                    println!("  Authenticated with derived K0 (re-burn)");
                    (s, false)
                }
                Err(e) => {
                    if is_auth_delay(&e) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    return Err(e).context(
                        "authentication failed with both factory and derived K0 — \
                         card may use a different issuer key",
                    );
                }
            }
        }
    };

    // Clear any residual SDM from a previous burn before writing NDEF.
    // SDM must be off when we write NDEF, otherwise the SDM engine processes
    // the placeholder bytes on readback and the verification comparison fails.
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let mut session = session;
    if settings.sdm.is_some() {
        println!("  Clearing residual SDM from previous burn...");
        let update = settings.into_update().with_sdm(Sdm::disabled());
        session = session
            .change_file_settings(transport, File::Ndef, &update)
            .await
            .context("failed to clear residual SDM")?;
    }

    // --- Write NDEF + verify prefix ---
    println!("[2/7] Writing NDEF template ({} bytes)...", plan.ndef_bytes.len());
    session
        .write_file_plain(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await
        .context("failed to write NDEF")?;

    let mut read_buf = [0u8; 256];
    let read_len = session
        .read_file_plain(transport, File::Ndef, 0, 0, &mut read_buf)
        .await
        .context("failed to read back NDEF for verification")?;

    // NDEF file is typically 256 bytes; only compare the bytes we actually wrote
    if read_len < plan.ndef_bytes.len()
        || read_buf[..plan.ndef_bytes.len()] != plan.ndef_bytes[..]
    {
        anyhow::bail!(
            "NDEF verification failed: wrote {} bytes, read back {} bytes — prefix mismatch.\n\
             Card state: NDEF may be corrupt, K0=factory → re-burn should fix this."
        , plan.ndef_bytes.len(), read_len);
    }
    println!("  ✓ NDEF verified ({} bytes written)", plan.ndef_bytes.len());

    // --- Configure SDM + verify ---
    println!("[3/7] Configuring SDM file settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read back file settings for verification")?;
    let session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &settings.into_update().with_sdm(plan.sdm_settings),
        )
        .await
        .context("failed to configure SDM")?;

    let (verify_settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to verify SDM file settings")?;
    if verify_settings.sdm.is_none() {
        anyhow::bail!(
            "SDM verification failed: file settings show no SDM configured.\n\
             Card state: NDEF correct, SDM not active, K0=factory → re-burn should fix this."
        );
    }
    println!("  ✓ SDM configured and verified");

    // --- Install K1-K4 ---
    let key_steps: [(NonMasterKeyNumber, &[u8; 16], &str); 4] = [
        (NonMasterKeyNumber::Key1, &keys.k1, "K1"),
        (NonMasterKeyNumber::Key2, &keys.k2, "K2"),
        (NonMasterKeyNumber::Key3, &keys.k3, "K3"),
        (NonMasterKeyNumber::Key4, &keys.k4, "K4"),
    ];
    let derived_keys = [&keys.k1, &keys.k2, &keys.k3, &keys.k4];

    let mut session = session;
    for (i, (key_no, new_key, label)) in key_steps.iter().enumerate() {
        let step = 4 + i;
        let old_key: &[u8; 16] = if old_keys_are_factory {
            &FACTORY_KEY
        } else {
            derived_keys[i]
        };
        println!("[{step}/7] Installing {label}...");
        match session
            .change_key(transport, *key_no, new_key, version, old_key)
            .await
        {
            Ok(s) => {
                println!("  ✓ {label} installed");
                session = s;
            }
            Err(e) => {
                let already_changed: Vec<&str> = key_steps[..i]
                    .iter()
                    .map(|(_, _, l)| *l)
                    .collect();
                anyhow::bail!(
                    "Failed to install {label}: {e:#}\n\
                     Card state: NDEF ✓, SDM ✓, K0=factory, changed keys: [{}]\n\
                     Recovery: re-run burn (factory K0 still active, changed keys will be overwritten)"
                 , already_changed.join(", "));
            }
        }
    }

    // --- Install K0 (master) ---
    println!("[7/7] Installing K0 (master key)...");
    session
        .change_master_key(transport, &keys.k0, version)
        .await
        .context(
            "Failed to install K0 (master key).\n\
             Card state: NDEF ✓, SDM ✓, K1-K4 changed, K0=factory.\n\
             Recovery: re-run burn immediately (factory K0 still active).",
        )?;
    println!("  ✓ K0 installed");

    // --- Post-burn verification ---
    println!("\nVerifying burn...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rnd_a = gen_rnd_a()?;
    let verify_session = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
        .await
    {
        Ok(s) => s,
        Err(e) if is_auth_delay(&e) => {
            println!("  Authentication delay, waiting 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let rnd_a = gen_rnd_a()?;
            Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
                .await
                .context(
                    "POST-BURN VERIFICATION FAILED: Cannot authenticate with new K0.\n\
                     Try: bolty-cli wipe and re-burn.",
                )?
        }
        Err(e) => {
            return Err(e).context(
                "POST-BURN VERIFICATION FAILED: Cannot authenticate with new K0.\n\
                 Try: bolty-cli wipe and re-burn.",
            );
        }
    };

    let (final_settings, _) = verify_session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("POST-BURN VERIFICATION FAILED: Cannot read file settings with new K0")?;

    if final_settings.sdm.is_none() {
        anyhow::bail!(
            "POST-BURN VERIFICATION FAILED: SDM not active after burn.\n\
             Card is authenticated with new K0 but SDM is missing."
        );
    }

    println!("  ✓ K0 authentication verified");
    println!("  ✓ SDM active");
    println!("\n✅ Card burned and verified successfully!");
    Ok(())
}

pub async fn cmd_wipe(
    transport: &mut PcscTransport,
    issuer_key: &[u8; 16],
    version: u8,
) -> anyhow::Result<()> {
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    let keys = BoltcardDeterministicDeriver::derive_keys(issuer_key, &uid_fixed, version as u32);
    println!("Derived K0: {}", crate::to_hex(keys.k0));

    // Probe card state: try factory K0 first, then derived K0
    let rnd_a = gen_rnd_a()?;
    // Factory K0 failure means card has derived keys — fall through to derived-K0 auth below.
    if let Ok(session) = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        let (settings, mut session) = session
            .get_file_settings(transport, File::Ndef)
            .await
            .context("failed to read file settings with factory K0")?;

        let has_sdm = settings.sdm.is_some();
        let mut buf = [0u8; 256];
        let len = session
            .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
            .await
            .context("failed to read NDEF with factory K0")?;
        let has_ndef = len >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);

        if !has_sdm && !has_ndef {
            println!("Card already wiped (factory keys, no SDM, empty NDEF). Nothing to do.");
            return Ok(());
        }
        anyhow::bail!(
            "Factory K0 works but card has residual state (SDM={}, NDEF={} bytes).\n\
             Card may have been partially wiped. Use `burn` to re-burn first, then `wipe`.",
            has_sdm,
            if has_ndef { len } else { 0 }
        );
    }

    println!("Authenticating with derived K0...");
    let rnd_a = gen_rnd_a()?;
    let session = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
        .await
    {
        Ok(s) => s,
        Err(e) if is_auth_delay(&e) => {
            println!("  Authentication delay, waiting 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let rnd_a = gen_rnd_a()?;
            Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
                .await
                .context(
                    "derived K0 authentication failed — wrong issuer key or card not burned",
                )?
        }
        Err(e) => {
            return Err(e).context(
                "derived K0 authentication failed — wrong issuer key or card not burned",
            )
        }
    };

    // Clear SDM by explicitly setting disabled SDM (not just into_update which preserves it)
    println!("Clearing SDM settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let update = settings.into_update().with_sdm(Sdm::disabled());
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await
        .context("failed to clear file settings")?;

    let empty_ndef = [0x00u8, 0x00];
    session
        .write_file_plain(transport, File::Ndef, 0, &empty_ndef)
        .await
        .context("failed to write empty NDEF")?;

    // Reset K1-K4 to factory
    let key_steps: [(NonMasterKeyNumber, &[u8; 16], &[u8; 16], &str); 4] = [
        (NonMasterKeyNumber::Key1, &FACTORY_KEY, &keys.k1, "K1"),
        (NonMasterKeyNumber::Key2, &FACTORY_KEY, &keys.k2, "K2"),
        (NonMasterKeyNumber::Key3, &FACTORY_KEY, &keys.k3, "K3"),
        (NonMasterKeyNumber::Key4, &FACTORY_KEY, &keys.k4, "K4"),
    ];

    let mut session = session;
    for (i, (key_no, new_key, old_key, label)) in key_steps.iter().enumerate() {
        println!("Resetting {label}...");
        match session
            .change_key(transport, *key_no, new_key, KEY_VERSION_BLANK, old_key)
            .await
        {
            Ok(s) => {
                println!("  ✓ {label} reset to factory");
                session = s;
            }
            Err(e) => {
                let already_reset: Vec<&str> = key_steps[..i]
                    .iter()
                    .map(|(_, _, _, l)| *l)
                    .collect();
                anyhow::bail!(
                    "Failed to reset {label}: {e:#}\n\
                     Card state: partially wiped (reset: [{}])\n\
                     Recovery: re-run burn, then wipe again",
                    already_reset.join(", ")
                );
            }
        }
    }

    println!("Resetting K0 (master key)...");
    session
        .change_master_key(transport, &FACTORY_KEY, KEY_VERSION_BLANK)
        .await
        .context("failed to reset master key")?;

    // --- Post-wipe verification ---
    println!("\nVerifying wipe...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rnd_a = gen_rnd_a()?;
    match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        Ok(verify) => {
            let (settings, mut verify) = verify
                .get_file_settings(transport, File::Ndef)
                .await
                .context("wipe verification: cannot read file settings")?;
            if let Some(ref sdm) = settings.sdm {
                let has_picc = !matches!(sdm.picc_data(), PiccData::None);
                let has_mac = sdm.file_read().is_some();
                if has_picc || has_mac {
                    anyhow::bail!(
                        "POST-WIPE WARNING: SDM still functionally active (picc={}, mac={})!",
                        has_picc, has_mac
                    );
                }
            }

            let mut buf = [0u8; 256];
            let len = verify
                .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
                .await
                .context("wipe verification: cannot read NDEF")?;
            // NDEF Type 4 Tag spec: first 2 bytes = NLEN (big-endian). NLEN=0 = empty.
            // The file may contain old data past byte 2; only NLEN matters.
            if len < 2 || buf[0] != 0x00 || buf[1] != 0x00 {
                anyhow::bail!(
                    "POST-WIPE WARNING: NDEF not empty ({} bytes: {})",
                    len,
                    crate::to_hex(&buf[..len.min(32)])
                );
            }
            println!("  ✓ Factory K0 works");
            println!("  ✓ SDM cleared");
            println!("  ✓ NDEF empty");
        }
        Err(e) => {
            anyhow::bail!(
                "POST-WIPE VERIFICATION FAILED: Cannot authenticate with factory K0.\n\
                 Card may be in an inconsistent state.\n\
                 Error: {e:#}"
            );
        }
    }

    println!("\n✅ Card wiped and verified successfully!");
    Ok(())
}

fn print_derived_keys(keys: &CardKeySet, version: u8) {
    println!("Derived keys (version {version}):");
    println!("  cardKey: {}", crate::to_hex(keys.card_key));
    println!("  K0:      {}", crate::to_hex(keys.k0));
    println!("  K1:      {}", crate::to_hex(keys.k1));
    println!("  K2:      {}", crate::to_hex(keys.k2));
    println!("  K3:      {}", crate::to_hex(keys.k3));
    println!("  K4:      {}", crate::to_hex(keys.k4));
}
